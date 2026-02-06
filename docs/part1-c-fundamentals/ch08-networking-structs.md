# Chapter 8: Networking Structs

This is the chapter where everything comes together. You have learned C types, pointers, structs, and bitwise operations. Now you will apply all of it to the data structures that define how network packets are laid out in memory.

Every eBPF program that touches network traffic parses these structures. When a packet arrives, it's just a sequence of bytes in memory. You cast those bytes to these structs and access fields like `ip->saddr` or `tcp->dest`. Understanding the memory layout of network headers is essential.

## Packet Structure Overview

A typical TCP/IP packet has layers, each with its own header:

```
┌──────────────────────────────────────────────────────┐
│                    Ethernet Header                    │
│                      (14 bytes)                       │
├──────────────────────────────────────────────────────┤
│                     IP Header                         │
│                    (20+ bytes)                        │
├──────────────────────────────────────────────────────┤
│                   TCP/UDP Header                      │
│                    (8-20+ bytes)                      │
├──────────────────────────────────────────────────────┤
│                      Payload                          │
│                   (variable size)                     │
└──────────────────────────────────────────────────────┘
```

In memory, these are contiguous bytes. You navigate from one layer to the next using pointer arithmetic:

```c
void *data = /* packet start */;

struct ethhdr *eth = data;
struct iphdr *ip = data + sizeof(struct ethhdr);
struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
```

## Byte Order: Network vs Host

This is the first thing you must understand. Different machines store multi-byte values in different orders:

- **Big-endian (network byte order)**: Most significant byte first. `0x1234` is stored as `12 34`.
- **Little-endian (host byte order on x86)**: Least significant byte first. `0x1234` is stored as `34 12`.

Network protocols use big-endian. Your x86 computer uses little-endian. Every time you read a multi-byte field from a packet, you must convert:

```c
// Reading port numbers from a packet
__u16 network_port = tcp->dest;             // Big-endian (network order)
__u16 host_port = bpf_ntohs(network_port);  // Converted to host order

// Writing port numbers to a packet
__u16 host_port = 8080;
tcp->dest = bpf_htons(host_port);  // Converted to network order
```

| Function | Direction | Meaning |
|----------|-----------|---------|
| `ntohs()` | Network → Host | 16-bit short |
| `htons()` | Host → Network | 16-bit short |
| `ntohl()` | Network → Host | 32-bit long |
| `htonl()` | Host → Network | 32-bit long |

In eBPF, use `bpf_ntohs()`, `bpf_htons()`, `bpf_ntohl()`, `bpf_htonl()` from `<bpf/bpf_endian.h>`.

!!! warning "Don't Forget Byte Order"
    Forgetting to convert byte order is one of the most common bugs. If you compare `tcp->dest` directly to `80`, you're comparing `0x5000` (80 in network order) to `0x0050` (80 in host order). They don't match!

    ```c
    // WRONG
    if (tcp->dest == 80) { ... }

    // RIGHT
    if (bpf_ntohs(tcp->dest) == 80) { ... }

    // Also RIGHT — convert the constant instead
    if (tcp->dest == bpf_htons(80)) { ... }
    ```

## Ethernet Header: `struct ethhdr`

Defined in `<linux/if_ether.h>`:

```c
struct ethhdr {
    unsigned char h_dest[ETH_ALEN];    // Destination MAC (6 bytes)
    unsigned char h_source[ETH_ALEN];  // Source MAC (6 bytes)
    __be16        h_proto;             // Protocol type (2 bytes)
};
// Total: 14 bytes
```

Memory layout:

```
Offset  Field       Size    Description
0       h_dest      6       Destination MAC address
6       h_source    6       Source MAC address
12      h_proto     2       EtherType (IP, ARP, IPv6, etc.)
```

Common protocol values (`h_proto`):

| Value | Constant | Protocol |
|-------|----------|----------|
| `0x0800` | `ETH_P_IP` | IPv4 |
| `0x0806` | `ETH_P_ARP` | ARP |
| `0x86DD` | `ETH_P_IPV6` | IPv6 |
| `0x8100` | `ETH_P_8021Q` | VLAN tagged |

### Parsing the Ethernet Header

```c
SEC("xdp")
int parse_eth(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Point to Ethernet header
    struct ethhdr *eth = data;

    // Bounds check: ensure we have a complete header
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    // Check if it's IPv4
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        // It's IPv4, continue parsing...
    }

    return XDP_PASS;
}
```

## IPv4 Header: `struct iphdr`

Defined in `<linux/ip.h>`:

```c
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8    ihl:4,      // Header length (in 32-bit words)
            version:4;  // IP version (4 for IPv4)
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u8    version:4,
            ihl:4;
#endif
    __u8    tos;        // Type of service
    __be16  tot_len;    // Total length of packet
    __be16  id;         // Identification
    __be16  frag_off;   // Fragment offset + flags
    __u8    ttl;        // Time to live
    __u8    protocol;   // Protocol (TCP=6, UDP=17, ICMP=1)
    __sum16 check;      // Header checksum
    __be32  saddr;      // Source IP address
    __be32  daddr;      // Destination IP address
    // Options may follow (if ihl > 5)
};
// Minimum: 20 bytes (ihl=5, meaning 5×4=20 bytes)
```

Memory layout (minimum 20 bytes):

```
Offset  Field     Size    Description
0       ver+ihl   1       Version (4 bits) + header length (4 bits)
1       tos       1       Type of service / DSCP
2       tot_len   2       Total packet length
4       id        2       Identification (for fragmentation)
6       frag_off  2       Flags (3 bits) + fragment offset (13 bits)
8       ttl       1       Time to live (hop count)
9       protocol  1       Upper layer protocol
10      check     2       Header checksum
12      saddr     4       Source IP address
16      daddr     4       Destination IP address
```

### Bit Fields

Notice `ihl:4` and `version:4`. These are **bit fields** — the compiler packs multiple fields into a single byte:

```c
__u8    ihl:4,      // Lower 4 bits
        version:4;  // Upper 4 bits
```

The order depends on endianness, which is why there's an `#if` for different byte orders.

### Parsing the IP Header

```c
SEC("xdp")
int parse_ip(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;  // Not IPv4

    // IP header starts after Ethernet
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    // Extract addresses (already in network byte order)
    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;

    // Protocol number (no conversion needed — single byte)
    __u8 proto = ip->protocol;

    // Check protocol
    if (proto == IPPROTO_TCP) {
        // Parse TCP header...
    }

    return XDP_PASS;
}
```

### Handling IP Options

The IP header can have options, making it longer than 20 bytes. The `ihl` field tells you the actual length:

```c
// ihl is header length in 32-bit words
// Multiply by 4 to get bytes
__u8 ip_hdr_len = ip->ihl * 4;

// TCP header starts after IP header (including options)
struct tcphdr *tcp = (void *)ip + ip_hdr_len;
```

!!! warning "Don't Assume 20-Byte IP Headers"
    While most IP packets have no options (ihl=5, 20 bytes), you should always use `ip->ihl * 4` to calculate the offset to the next header. Assuming 20 bytes will cause you to parse garbage when options are present.

## TCP Header: `struct tcphdr`

Defined in `<linux/tcp.h>`:

```c
struct tcphdr {
    __be16  source;     // Source port
    __be16  dest;       // Destination port
    __be32  seq;        // Sequence number
    __be32  ack_seq;    // Acknowledgment number
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u16   res1:4,     // Reserved
            doff:4,     // Data offset (header length in 32-bit words)
            fin:1,      // FIN flag
            syn:1,      // SYN flag
            rst:1,      // RST flag
            psh:1,      // PSH flag
            ack:1,      // ACK flag
            urg:1,      // URG flag
            ece:1,      // ECE flag
            cwr:1;      // CWR flag
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u16   doff:4,
            res1:4,
            cwr:1,
            ece:1,
            urg:1,
            ack:1,
            psh:1,
            rst:1,
            syn:1,
            fin:1;
#endif
    __be16  window;     // Window size
    __sum16 check;      // Checksum
    __be16  urg_ptr;    // Urgent pointer
    // Options may follow
};
// Minimum: 20 bytes (doff=5)
```

### TCP Flags

The individual flag bits can be accessed directly (`tcp->syn`, `tcp->ack`) or through the combined flags byte. In some contexts, you'll see flags defined as constants:

```c
// TCP flag constants (for use with the flags byte)
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PSH  0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
```

### Parsing TCP

```c
SEC("xdp")
int parse_tcp(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // Calculate TCP header offset (accounting for IP options)
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return XDP_DROP;

    // Extract ports (remember byte order!)
    __u16 src_port = bpf_ntohs(tcp->source);
    __u16 dst_port = bpf_ntohs(tcp->dest);

    // Check for SYN packet (new connection)
    if (tcp->syn && !tcp->ack) {
        // This is a SYN packet
    }

    // Check if destination is port 80
    if (dst_port == 80) {
        // HTTP traffic
    }

    return XDP_PASS;
}
```

## UDP Header: `struct udphdr`

Defined in `<linux/udp.h>`:

```c
struct udphdr {
    __be16  source;     // Source port
    __be16  dest;       // Destination port
    __be16  len;        // Length (header + data)
    __sum16 check;      // Checksum
};
// Always 8 bytes
```

UDP is much simpler than TCP — fixed 8-byte header, no flags, no connection state.

```c
if (ip->protocol == IPPROTO_UDP) {
    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end)
        return XDP_DROP;

    __u16 src_port = bpf_ntohs(udp->source);
    __u16 dst_port = bpf_ntohs(udp->dest);

    // DNS is UDP port 53
    if (dst_port == 53) {
        // DNS query
    }
}
```

## ICMP Header: `struct icmphdr`

Defined in `<linux/icmp.h>`:

```c
struct icmphdr {
    __u8    type;       // Message type
    __u8    code;       // Type sub-code
    __sum16 checksum;   // Checksum
    union {
        struct {
            __be16  id;
            __be16  sequence;
        } echo;         // For echo request/reply
        __be32  gateway; // For redirect
        struct {
            __be16  __unused;
            __be16  mtu;
        } frag;         // For fragmentation needed
    } un;
};
```

Common ICMP types:

| Type | Code | Meaning |
|------|------|---------|
| 0 | 0 | Echo Reply (ping response) |
| 8 | 0 | Echo Request (ping) |
| 3 | * | Destination Unreachable |
| 11 | * | Time Exceeded |

## Socket Address Structures

When working with cgroup hooks or socket operations, you'll use socket address structures:

### IPv4: `struct sockaddr_in`

```c
struct sockaddr_in {
    __kernel_sa_family_t sin_family;  // AF_INET
    __be16               sin_port;    // Port number
    struct in_addr       sin_addr;    // IP address
    // Padding to make it same size as sockaddr
};

struct in_addr {
    __be32 s_addr;  // 32-bit IPv4 address
};
```

### IPv6: `struct sockaddr_in6`

```c
struct sockaddr_in6 {
    unsigned short sin6_family;    // AF_INET6
    __be16         sin6_port;      // Port number
    __be32         sin6_flowinfo;  // Flow information
    struct in6_addr sin6_addr;     // IPv6 address
    __u32          sin6_scope_id;  // Scope ID
};

struct in6_addr {
    union {
        __u8  u6_addr8[16];
        __be16 u6_addr16[8];
        __be32 u6_addr32[4];
    } in6_u;
};
```

## Converting IP Addresses to Strings

In userspace, you convert IP addresses to readable strings:

=== "Python"

    ```python
    import socket
    import struct

    # Integer to string
    ip_int = 0x0A000001  # 10.0.0.1 in host byte order
    ip_bytes = struct.pack('>I', ip_int)  # Convert to big-endian bytes
    ip_str = socket.inet_ntoa(ip_bytes)    # "10.0.0.1"

    # String to integer
    ip_str = "192.168.1.1"
    ip_bytes = socket.inet_aton(ip_str)
    ip_int = struct.unpack('>I', ip_bytes)[0]  # 3232235777
    ```

=== "C"

    ```c
    #include <arpa/inet.h>

    // Integer to string
    __u32 ip_net = 0x0100000A;  // 10.0.0.1 in network byte order
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_net, ip_str, sizeof(ip_str));
    // ip_str = "10.0.0.1"

    // String to integer
    char *ip_str = "192.168.1.1";
    __u32 ip_net;
    inet_pton(AF_INET, ip_str, &ip_net);
    // ip_net = 0x0101A8C0 (network byte order)
    ```

!!! note "String Conversion in eBPF"
    String conversion functions like `inet_ntop()` are **not available in eBPF programs** (they're userspace functions). In eBPF, you work with raw addresses and convert to strings only in your userspace code when displaying results.

## Complete Packet Parsing Example

Here's a complete example that parses TCP packets and extracts the 5-tuple:

```c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct five_tuple {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
};

SEC("xdp")
int extract_tuple(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct five_tuple tuple = {};

    // Layer 2: Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Layer 3: IP
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    tuple.src_ip = ip->saddr;
    tuple.dst_ip = ip->daddr;
    tuple.protocol = ip->protocol;

    // Layer 4: TCP or UDP
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return XDP_DROP;

        tuple.src_port = tcp->source;
        tuple.dst_port = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return XDP_DROP;

        tuple.src_port = udp->source;
        tuple.dst_port = udp->dest;
    }

    // Now tuple contains the 5-tuple
    // Could store in a map, log, etc.

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
```

## Exercises

1. **Header size verification**: Write a program that prints `sizeof()` for `ethhdr`, `iphdr`, `tcphdr`, and `udphdr`. Verify they match the expected sizes (14, 20, 20, 8 bytes).

2. **Byte order practice**: Given the bytes `0x01 0xBB` (representing port 443 in network order), manually calculate what the host-order value is on a little-endian machine. Verify with code.

3. **IP address parsing**: Write a function that takes a `__u32` IP address in network byte order and prints it in dotted-decimal notation (e.g., "192.168.1.1").

4. **TCP flag decoder**: Write a function that takes the TCP flags byte and prints which flags are set (SYN, ACK, FIN, RST, PSH, URG).

5. **Packet builder**: In Python using `struct.pack()`, build the binary representation of an Ethernet header with a specific source MAC, destination MAC, and EtherType. Compare to what the C struct would produce.

6. **Bounds check practice**: Trace through the complete parsing example and identify every bounds check. What happens if you remove each one? Which would the verifier catch vs which would be runtime bugs?

7. **IPv6 extension**: Modify the complete example to also handle IPv6 packets. You'll need to include `<linux/ipv6.h>` and add parsing for `struct ipv6hdr`.
