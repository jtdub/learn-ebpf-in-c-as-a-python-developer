# Chapter 18: Socket Syscalls

Before you can intercept network connections with eBPF, you need to understand what happens when an application makes a network call. Every Python `requests.get()`, every `socket.connect()`, every `curl` command eventually becomes a **system call** -- a request from userspace to the kernel. This chapter maps out those syscalls so you know exactly where eBPF can hook in.

## The Socket Syscall Family

Linux provides a small set of syscalls for networking. If you have used Python's `socket` module, you have already used thin wrappers around these exact kernel interfaces:

=== "Python"

    ```python
    import socket

    # socket() — create a socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # connect() — initiate a connection to a remote address
    sock.connect(("93.184.216.34", 80))

    # sendmsg() — send data (Python uses send/sendall, which call sendmsg)
    sock.send(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

    # recvmsg() — receive data
    data = sock.recv(4096)

    # close() — tear down
    sock.close()
    ```

=== "C"

    ```c
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <unistd.h>

    // socket() — create a socket
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(80),
        .sin_addr.s_addr = inet_addr("93.184.216.34"),
    };

    // connect() — initiate a connection
    connect(fd, (struct sockaddr *)&addr, sizeof(addr));

    // sendmsg() — send data
    char *request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    send(fd, request, strlen(request), 0);

    // recvmsg() — receive data
    char buf[4096];
    recv(fd, buf, sizeof(buf), 0);

    // close() — tear down
    close(fd);
    ```

The Python version hides all the struct setup and type casting, but it calls the same kernel functions.

## Each Syscall Explained

### socket() -- Create a Communication Endpoint

```c
int socket(int domain, int type, int protocol);
```

This creates a socket file descriptor. It does **not** establish any connection or send any data. Think of it as allocating a mailbox -- you have a box, but no address and no letters yet.

- `domain`: Address family (`AF_INET` for IPv4, `AF_INET6` for IPv6, `AF_UNIX` for local)
- `type`: Socket type (`SOCK_STREAM` for TCP, `SOCK_DGRAM` for UDP, `SOCK_RAW` for raw packets)
- `protocol`: Usually 0 (auto-select), or `IPPROTO_TCP`, `IPPROTO_UDP` explicitly

Inside the kernel, `socket()` allocates a `struct socket` and a `struct sock`, sets up the protocol operations table, and returns a file descriptor integer.

!!! note "Python Parallel"
    `socket.socket(socket.AF_INET, socket.SOCK_STREAM)` in Python maps directly to `socket(AF_INET, SOCK_STREAM, 0)` in C. Python just wraps the returned integer fd in a socket object that has `.send()`, `.recv()` methods.

### bind() -- Assign a Local Address

```c
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
```

Assigns a local IP address and port to the socket. Servers call this to say "listen on port 8080." Clients usually skip `bind()` and let the kernel pick an ephemeral port.

```c
struct sockaddr_in local = {
    .sin_family = AF_INET,
    .sin_port = htons(8080),
    .sin_addr.s_addr = INADDR_ANY,   // bind to all interfaces
};
bind(fd, (struct sockaddr *)&local, sizeof(local));
```

!!! warning "eBPF Hook Point"
    eBPF `cgroup/bind4` and `cgroup/bind6` programs intercept `bind()` calls. You can inspect what port and address an application is trying to bind to, modify the address, or block the bind entirely. We cover this in [Chapter 19](ch19-cgroup-hooks.md).

### listen() -- Mark Socket as Passive

```c
int listen(int sockfd, int backlog);
```

Tells the kernel this socket will accept incoming connections rather than initiate outgoing ones. The `backlog` parameter sets the maximum queue length for pending connections.

In Python, this is `sock.listen(128)`. The kernel sets up the SYN queue (half-open connections) and the accept queue (fully established connections waiting for `accept()`).

### accept() -- Accept an Incoming Connection

```c
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
```

Blocks until a client connects, then returns a **new** file descriptor for that specific connection. The original socket continues listening.

```c
struct sockaddr_in client_addr;
socklen_t len = sizeof(client_addr);
int client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &len);
// client_addr now contains the remote IP and port
```

=== "Python"

    ```python
    # Python's accept() returns (socket_object, address_tuple)
    client_sock, (client_ip, client_port) = server_sock.accept()
    print(f"Connection from {client_ip}:{client_port}")
    ```

=== "C"

    ```c
    // C's accept() returns a raw fd; address is via output parameter
    struct sockaddr_in client_addr;
    socklen_t len = sizeof(client_addr);
    int client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &len);

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, ip_str, sizeof(ip_str));
    printf("Connection from %s:%d\n", ip_str, ntohs(client_addr.sin_port));
    ```

### connect() -- Initiate a Connection

```c
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
```

This is the most important syscall for understanding eBPF packet interception. For TCP, `connect()` triggers the entire three-way handshake. For UDP, it just sets the default destination address (no packets are sent).

!!! danger "This is THE Key Interception Point"
    When a Python application calls `requests.get("http://10.0.0.5:80/")`, it eventually calls `connect()` with the destination address `10.0.0.5:80`. An eBPF cgroup hook on `connect()` can **see** this destination and **change** it -- for example, redirecting it to `127.0.0.1:15001` (a local proxy). The application never knows the redirect happened. This is how transparent proxying works in Kubernetes service meshes.

### sendmsg() / recvmsg() -- Transfer Data

```c
ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);
ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);
```

These are the general-purpose data transfer syscalls. `send()`, `write()`, `sendto()` are all simpler wrappers that eventually call `sendmsg()` internally. Similarly, `recv()`, `read()`, `recvfrom()` map to `recvmsg()`.

For UDP specifically, `sendmsg()` is important because each call sends a complete datagram, and the destination address can be specified per-message:

```c
struct sockaddr_in dest = {
    .sin_family = AF_INET,
    .sin_port = htons(53),
    .sin_addr.s_addr = inet_addr("8.8.8.8"),
};
// sendto is a simpler wrapper around sendmsg
sendto(fd, query, query_len, 0, (struct sockaddr *)&dest, sizeof(dest));
```

!!! warning "eBPF Hook Point"
    `cgroup/sendmsg4` and `cgroup/sendmsg6` let you intercept UDP `sendmsg()` calls and rewrite the destination address. This is how eBPF can redirect DNS queries or other UDP traffic transparently.

## The struct sockaddr_in Review

Every socket syscall that involves an address uses `struct sockaddr_in` (IPv4) or `struct sockaddr_in6` (IPv6). You encountered this in Part 1, Chapter 8. Here is the layout again, since you will see it constantly in Part 3:

```
struct sockaddr_in (16 bytes total)
┌──────────────────┬──────────────────┬──────────────────────────────┐
│  sin_family (2B) │  sin_port (2B)   │  sin_addr.s_addr (4B)       │
│  AF_INET = 2     │  network byte    │  network byte order         │
│                  │  order (big-     │  e.g., 0x0A000005 =         │
│                  │  endian)         │  10.0.0.5                   │
├──────────────────┴──────────────────┴──────────────────────────────┤
│  sin_zero[8] — padding (8 bytes, must be zero)                    │
└───────────────────────────────────────────────────────────────────┘
```

```c
struct sockaddr_in {
    sa_family_t    sin_family;  // AF_INET (always 2 for IPv4)
    in_port_t      sin_port;    // Port in network byte order
    struct in_addr sin_addr;    // IP address in network byte order
    char           sin_zero[8]; // Padding
};
```

!!! tip "Byte Order Reminder"
    Network byte order is big-endian. x86 CPUs are little-endian. You must use `htons()` (host to network short) for ports and `htonl()` (host to network long) for IP addresses. In eBPF, use `bpf_htons()` and `bpf_htonl()`. Forgetting byte conversion is the #1 source of "my program runs but nothing matches" bugs.

## The Journey of connect()

Let's trace what happens when your Python application calls `sock.connect(("10.0.0.5", 80))`. This is the exact flow that eBPF hooks into:

```
 USERSPACE                        KERNEL
 ─────────                        ──────

 Python: sock.connect(            1. Python's socket module calls
   ("10.0.0.5", 80))                 glibc connect() wrapper
         │
         ▼
 glibc: connect(fd,              2. glibc issues the connect()
   &sockaddr_in, len)                syscall via SYSCALL instruction
         │
         ▼
 ─── syscall boundary ──────────────────────────────

         │
         ▼
 sys_connect()                   3. Kernel entry point.
         │                          Copies sockaddr from userspace.
         │
         ▼
 ┌─────────────────────┐
 │ CGROUP BPF HOOKS    │        4. If a BPF_PROG_TYPE_CGROUP_SOCK_ADDR
 │ (cgroup/connect4)   │           program is attached, it runs HERE.
 │                     │           It can:
 │ - Read dest IP/port │           - Inspect the destination
 │ - Modify dest IP    │           - Change the destination IP/port
 │ - Modify dest port  │           - Block the connection (return 0)
 │ - Block connection  │
 └────────┬────────────┘
          │
          ▼
 security_socket_connect()      5. LSM security check (SELinux, etc.)
          │
          ▼
 inet_stream_connect()          6. Protocol-specific connect handler.
          │                        For TCP: allocates a struct sock,
          ▼                        begins the three-way handshake.
 tcp_v4_connect()
          │
          ▼
 ip_route_output()              7. Routing lookup — which interface
          │                        and next-hop to use.
          ▼
 ip_local_out()                 8. Build the IP header, compute
          │                        checksum.
          ▼
 ┌─────────────────────┐
 │ TC EGRESS BPF HOOK  │       9. If a TC egress program is attached,
 │                     │          it can inspect/modify the SYN packet.
 └────────┬────────────┘
          │
          ▼
 dev_queue_xmit()              10. Packet is queued for transmission
          │                        by the network driver.
          ▼
 ═══ NIC (wire) ═══════════════════════════════════
```

!!! note "Why This Matters"
    Step 4 is where `cgroup/connect4` eBPF programs run. The application has already committed to connecting to `10.0.0.5:80`, but the kernel has **not yet created a SYN packet or done any routing**. This means the eBPF program can silently change the destination address, and the kernel will happily build a SYN packet for the new address instead. The application has no idea the redirect happened.

## Server-Side Syscall Flow

For servers, the flow is different. Here is what happens for a simple Python TCP server:

```python
import socket

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("0.0.0.0", 8080))    # bind()    <-- cgroup/bind4 hook
server.listen(128)                  # listen()

while True:
    client, addr = server.accept()  # accept()  <-- blocks until connection
    data = client.recv(4096)        # recvmsg()
    client.send(b"HTTP/1.1 200 OK\r\n\r\nHello")  # sendmsg()
    client.close()
```

The kernel-side flow for the incoming connection:

```
 NIC receives SYN packet
         │
         ▼
 ┌─────────────────────┐
 │ XDP HOOK            │    Earliest hook — can drop before sk_buff
 └────────┬────────────┘
          │
          ▼
 sk_buff allocated
          │
          ▼
 ┌─────────────────────┐
 │ TC INGRESS HOOK     │    Can inspect/modify the SYN packet
 └────────┬────────────┘
          │
          ▼
 ip_rcv() → tcp_v4_rcv()   IP and TCP processing
          │
          ▼
 SYN added to listen queue
          │
          ▼
 SYN-ACK sent back          Three-way handshake continues
          │
          ▼
 ACK received → connection
 moved to accept queue
          │
          ▼
 accept() returns to         Application gets the new fd
 userspace
```

## The Kernel Data Structures

When you trace a connection in the kernel, several key structures are involved. You do not need to memorize these, but knowing they exist helps when reading eBPF context structs:

```c
struct socket {
    socket_state         state;     // SS_UNCONNECTED, SS_CONNECTED, etc.
    short                type;      // SOCK_STREAM, SOCK_DGRAM
    struct sock         *sk;        // The protocol-specific socket
    const struct proto_ops *ops;    // Protocol operations (connect, bind, etc.)
};

struct sock {
    struct sock_common  __sk_common; // Holds IP addresses, ports
    // ... hundreds of fields for TCP state, buffers, etc.
};

struct sock_common {
    union {
        struct {
            __be32     skc_daddr;   // Foreign (destination) IPv4 addr
            __be32     skc_rcv_saddr; // Bound local IPv4 addr
        };
    };
    unsigned short       skc_num;   // Local port
    __be16               skc_dport; // Destination port (network byte order)
    unsigned short       skc_family;// Address family (AF_INET, AF_INET6)
    // ...
};
```

!!! tip "From Python to Kernel"
    When you call `sock.connect(("10.0.0.5", 80))` in Python, the kernel fills in `skc_daddr = 10.0.0.5` and `skc_dport = 80` in the `struct sock_common`. eBPF programs that attach to socket operations (sock_ops) can read these fields to learn where a connection is going.

## How UDP Differs

TCP uses `connect()` + `accept()` for connection setup. UDP is connectionless -- there is no handshake. The key difference for eBPF:

| | TCP | UDP |
|---|---|---|
| **Connection setup** | `connect()` triggers SYN/SYN-ACK/ACK | `connect()` just sets default dest (no packets) |
| **Data transfer** | `send()` -- data flows over established connection | `sendto()` / `sendmsg()` -- each datagram can go to different dest |
| **eBPF interception** | Hook `connect()` to intercept before handshake | Hook `sendmsg()` to intercept each datagram |
| **Cgroup hooks** | `cgroup/connect4` | `cgroup/sendmsg4` (per-datagram interception) |

For UDP, the `sendmsg()` hook is more important than `connect()` because many UDP applications use `sendto()` without ever calling `connect()`.

## Putting It Together: Where eBPF Fits

Here is a consolidated view of which eBPF program types can intercept which syscalls:

| Syscall | eBPF Hook | Program Type | What You Can Do |
|---------|-----------|-------------|-----------------|
| `connect()` | `cgroup/connect4`, `cgroup/connect6` | `CGROUP_SOCK_ADDR` | Read/modify dest IP and port, block |
| `bind()` | `cgroup/bind4`, `cgroup/bind6` | `CGROUP_SOCK_ADDR` | Read/modify bind address, block |
| `sendmsg()` | `cgroup/sendmsg4`, `cgroup/sendmsg6` | `CGROUP_SOCK_ADDR` | Read/modify dest of UDP datagrams |
| `recvmsg()` | `cgroup/recvmsg4`, `cgroup/recvmsg6` | `CGROUP_SOCK_ADDR` | Rewrite source addr of received UDP |
| (packet arrives) | XDP | `XDP` | Drop, pass, redirect raw packets |
| (packet arrives) | TC ingress | `SCHED_CLS` | Inspect/modify packets with sk_buff |
| (packet leaves) | TC egress | `SCHED_CLS` | Inspect/modify outgoing packets |
| `send()` / `write()` | sk_msg | `SK_MSG` | Redirect message to another socket |
| (any socket op) | sock_ops | `SOCK_OPS` | Monitor/modify socket events |

## Exercises

### Exercise 18.1: Trace connect() with strace

Run `strace -e trace=connect python3 -c "import urllib.request; urllib.request.urlopen('http://example.com')"` and identify each `connect()` call. Note the `sockaddr_in` structures in the output. Which one is the DNS query? Which one is the HTTP connection?

### Exercise 18.2: Map Python to Syscalls

Write a Python TCP server and a Python TCP client. Run both under `strace -e trace=network` and identify every socket syscall (socket, bind, listen, accept, connect, sendto, recvfrom). Map each strace line to the corresponding Python code.

### Exercise 18.3: Examine struct sockaddr_in

Write a C program that creates a `struct sockaddr_in` for the address `192.168.1.100:443`, then prints each byte of the struct using a `unsigned char *` pointer. Verify that `sin_port` is stored in big-endian (network byte order) and that `sin_addr` is also big-endian.

```c
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main() {
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(443),
        .sin_addr.s_addr = inet_addr("192.168.1.100"),
    };

    unsigned char *bytes = (unsigned char *)&addr;
    for (int i = 0; i < sizeof(addr); i++) {
        printf("byte[%2d] = 0x%02x\n", i, bytes[i]);
    }
    return 0;
}
```

### Exercise 18.4: UDP vs TCP Syscall Differences

Write two Python programs: one that sends a UDP datagram to `8.8.8.8:53` using `sendto()`, and one that connects to `example.com:80` via TCP. Run both under `strace` and compare the syscall sequences. Note which syscalls are present for TCP but absent for UDP.

### Exercise 18.5: The accept() Return Value

Write a Python server that prints the file descriptor number of each accepted connection (use `client_sock.fileno()`). Accept 5 connections and observe how the fd numbers increment. This demonstrates how the kernel allocates new file descriptors for each `accept()` call.

---

Next: [Chapter 19: Cgroup Hooks](ch19-cgroup-hooks.md) -- where we write our first eBPF programs that intercept these syscalls.
