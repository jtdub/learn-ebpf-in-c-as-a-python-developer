# Chapter 19: Cgroup Hooks

Cgroups (control groups) organize processes hierarchically. eBPF can attach to cgroup hooks to filter or monitor network traffic for all processes in a cgroup — perfect for container-level network policies.

This chapter covers cgroup-based eBPF programs for network control.

## What are Cgroups?

Cgroups group processes for resource management:

```
/sys/fs/cgroup/
├── system.slice/           # System services
│   ├── docker.service/
│   └── nginx.service/
├── user.slice/             # User sessions
│   └── user-1000.slice/
└── docker/                 # Docker containers
    ├── container_abc123/
    └── container_def456/
```

Every process belongs to a cgroup. eBPF can intercept network operations at the cgroup level.

## Cgroup eBPF Program Types

| Type | Hook Point | Use Case |
|------|------------|----------|
| `BPF_PROG_TYPE_CGROUP_SKB` | Ingress/egress packets | Packet filtering |
| `BPF_PROG_TYPE_CGROUP_SOCK` | Socket creation | Allow/deny sockets |
| `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` | Connect/bind/sendmsg | Address filtering |
| `BPF_PROG_TYPE_SOCK_OPS` | Socket operations | TCP tuning |
| `BPF_PROG_TYPE_CGROUP_SOCKOPT` | getsockopt/setsockopt | Socket option control |

## Cgroup SKB Programs

### Ingress Filtering

Filter packets entering processes in a cgroup:

=== "BCC"

    ```python
    #!/usr/bin/env python3
    from bcc import BPF
    import sys

    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <cgroup_path>")
        sys.exit(1)

    cgroup_path = sys.argv[1]

    program = r"""
    #include <linux/bpf.h>
    #include <linux/if_ether.h>
    #include <linux/ip.h>
    #include <linux/tcp.h>

    int cgroup_ingress(struct __sk_buff *skb) {
        void *data = (void *)(long)skb->data;
        void *data_end = (void *)(long)skb->data_end;

        struct iphdr *ip = data + sizeof(struct ethhdr);
        if ((void *)(ip + 1) > data_end)
            return 1;  // Allow if can't parse

        // Block traffic from 10.0.0.0/8
        __u32 src = ip->saddr;
        if ((src & 0x000000FF) == 0x0000000A)  // 10.x.x.x
            return 0;  // Drop

        return 1;  // Allow
    }
    """

    b = BPF(text=program)
    fn = b.load_func("cgroup_ingress", BPF.CGROUP_SKB)
    b.attach_cgroup(cgroup_path, fn, BPF.CGROUP_INET_INGRESS)

    print(f"Filtering ingress on {cgroup_path}. Ctrl+C to exit.")
    try:
        while True:
            pass
    except KeyboardInterrupt:
        pass
    ```

=== "libbpf"

    ```c
    // cgroup_filter.bpf.c
    #include "vmlinux.h"
    #include <bpf/bpf_helpers.h>

    SEC("cgroup_skb/ingress")
    int cgroup_ingress(struct __sk_buff *skb) {
        // For cgroup_skb, we use skb->protocol, not parsing ethhdr
        if (skb->protocol != __builtin_bswap16(ETH_P_IP))
            return 1;  // Not IPv4, allow

        __u32 src = skb->remote_ip4;

        // Block 10.0.0.0/8
        if ((src & 0x000000FF) == 0x0000000A)
            return 0;  // Drop

        return 1;  // Allow
    }

    char LICENSE[] SEC("license") = "GPL";
    ```

### Egress Filtering

Control outgoing traffic:

```c
SEC("cgroup_skb/egress")
int cgroup_egress(struct __sk_buff *skb) {
    // Block connections to port 80
    if (skb->protocol == __builtin_bswap16(ETH_P_IP)) {
        // For TCP, check destination port
        if (skb->remote_port == 80)
            return 0;  // Drop
    }

    return 1;  // Allow
}
```

### Return Values

For cgroup_skb programs:

| Value | Meaning |
|-------|---------|
| `0` | Drop packet |
| `1` | Allow packet |
| `2+` | Allow (some contexts interpret differently) |

## Cgroup Socket Programs

### Controlling Socket Creation

Decide whether a process can create sockets:

```c
SEC("cgroup/sock_create")
int sock_create(struct bpf_sock *sk) {
    // Only allow TCP and UDP sockets
    if (sk->type != SOCK_STREAM && sk->type != SOCK_DGRAM)
        return 0;  // Block

    // Only allow IPv4
    if (sk->family != AF_INET)
        return 0;  // Block

    return 1;  // Allow
}
```

### Socket Release Hook

Track when sockets close:

```c
SEC("cgroup/sock_release")
int sock_release(struct bpf_sock *sk) {
    // Log or track socket closure
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("Socket closed by PID %d\n", pid);
    return 1;
}
```

## Cgroup Socket Address Programs

These hook into address operations: connect, bind, sendmsg, recvmsg, getpeername.

### Filtering Connect

Block or modify connection attempts:

```c
SEC("cgroup/connect4")  // IPv4 connect
int connect4(struct bpf_sock_addr *ctx) {
    // ctx->user_ip4 is the destination IP
    // ctx->user_port is the destination port (network byte order)

    __u32 dst_ip = ctx->user_ip4;
    __u16 dst_port = __builtin_bswap16(ctx->user_port);

    // Block connections to 192.168.1.100
    if (dst_ip == 0x6401A8C0)  // 192.168.1.100 in little-endian
        return 0;  // Block

    // Block connections to port 22
    if (dst_port == 22)
        return 0;  // Block

    return 1;  // Allow
}
```

### Redirecting Connections

Transparently redirect connections:

```c
SEC("cgroup/connect4")
int redirect_connect(struct bpf_sock_addr *ctx) {
    // Redirect all connections to 10.0.0.1:8080 -> 127.0.0.1:3128

    if (ctx->user_ip4 == 0x0100000A &&  // 10.0.0.1
        ctx->user_port == __builtin_bswap16(8080)) {
        ctx->user_ip4 = 0x0100007F;     // 127.0.0.1
        ctx->user_port = __builtin_bswap16(3128);
    }

    return 1;
}
```

### Controlling Bind

Restrict which ports processes can bind:

```c
SEC("cgroup/bind4")
int bind4(struct bpf_sock_addr *ctx) {
    __u16 port = __builtin_bswap16(ctx->user_port);

    // Only allow binding to ports >= 1024 (non-privileged)
    if (port > 0 && port < 1024)
        return 0;  // Block

    return 1;  // Allow
}
```

### Sendmsg/Recvmsg Filtering

```c
SEC("cgroup/sendmsg4")
int sendmsg4(struct bpf_sock_addr *ctx) {
    // For UDP: filter where messages are sent
    __u32 dst = ctx->user_ip4;

    // Block sending to multicast (224.0.0.0/4)
    if ((dst & 0x000000F0) == 0x000000E0)
        return 0;

    return 1;
}
```

## Socket Operations (sock_ops)

`sock_ops` programs hook into TCP state machine events. Great for connection tracking and TCP tuning.

### Connection Events

```c
SEC("sockops")
int sock_ops_prog(struct bpf_sock_ops *skops) {
    switch (skops->op) {
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        // Outgoing connection established
        bpf_printk("Active connection to %pI4:%d\n",
                   &skops->remote_ip4, skops->remote_port);
        break;

    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        // Incoming connection accepted
        bpf_printk("Passive connection from %pI4:%d\n",
                   &skops->remote_ip4, skops->remote_port);
        break;

    case BPF_SOCK_OPS_STATE_CB:
        // TCP state change
        if (skops->args[1] == TCP_CLOSE)
            bpf_printk("Connection closed\n");
        break;
    }

    return 1;
}
```

### Callback Flags

You must enable callbacks explicitly:

```c
SEC("sockops")
int sockops_init(struct bpf_sock_ops *skops) {
    // Enable state change callbacks
    bpf_sock_ops_cb_flags_set(skops,
        BPF_SOCK_OPS_STATE_CB_FLAG |
        BPF_SOCK_OPS_RTT_CB_FLAG);
    return 1;
}
```

### TCP Tuning

```c
SEC("sockops")
int tcp_tuning(struct bpf_sock_ops *skops) {
    if (skops->op == BPF_SOCK_OPS_TCP_CONNECT_CB) {
        // Set initial congestion window
        bpf_setsockopt(skops, SOL_TCP, TCP_BPF_IW, &(int){20}, sizeof(int));

        // Set SYN_RTO
        bpf_setsockopt(skops, SOL_TCP, TCP_BPF_SYN_RTO, &(int){500}, sizeof(int));
    }

    return 1;
}
```

## Socket Option Programs

Control getsockopt/setsockopt calls:

```c
SEC("cgroup/getsockopt")
int getsockopt_prog(struct bpf_sockopt *ctx) {
    // Log socket option reads
    bpf_printk("getsockopt level=%d optname=%d\n",
               ctx->level, ctx->optname);
    return 1;
}

SEC("cgroup/setsockopt")
int setsockopt_prog(struct bpf_sockopt *ctx) {
    // Prevent setting SO_REUSEPORT
    if (ctx->level == SOL_SOCKET && ctx->optname == SO_REUSEPORT) {
        ctx->retval = -EPERM;
        return 0;  // Block
    }
    return 1;
}
```

## Attaching to Cgroups

### Using BCC

```python
from bcc import BPF

b = BPF(text=program)
fn = b.load_func("my_prog", BPF.CGROUP_SKB)
# or: BPF.CGROUP_SOCK, BPF.CGROUP_SOCK_ADDR, etc.

# Attach to cgroup
b.attach_cgroup("/sys/fs/cgroup/my_cgroup", fn, BPF.CGROUP_INET_INGRESS)
# or: BPF.CGROUP_INET_EGRESS, BPF.CGROUP_INET4_CONNECT, etc.
```

### Using bpftool

```bash
# Attach
sudo bpftool cgroup attach /sys/fs/cgroup/test ingress pinned /sys/fs/bpf/my_prog

# List
sudo bpftool cgroup show /sys/fs/cgroup/test

# Detach
sudo bpftool cgroup detach /sys/fs/cgroup/test ingress pinned /sys/fs/bpf/my_prog
```

### Cgroup v1 vs v2

| Feature | Cgroup v1 | Cgroup v2 |
|---------|-----------|-----------|
| Hierarchy | Multiple | Single unified |
| eBPF support | Limited | Full |
| Default (modern) | Legacy | Preferred |

Most modern systems use cgroup v2. Check:

```bash
mount | grep cgroup
# cgroup2 on /sys/fs/cgroup type cgroup2
```

## Full Example: Container Network Policy

```python
#!/usr/bin/env python3
"""
Block container from accessing specific IPs.
Usage: sudo python3 container_policy.py /sys/fs/cgroup/docker/<container_id>
"""
from bcc import BPF
import sys
import ctypes
import struct

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <cgroup_path> [blocked_ips...]")
    sys.exit(1)

cgroup_path = sys.argv[1]
blocked_ips = sys.argv[2:] if len(sys.argv) > 2 else ["93.184.216.34"]  # example.com

program = r"""
#include <linux/bpf.h>
#include <linux/ip.h>

BPF_HASH(blocked, u32, u8, 1024);
BPF_PERCPU_ARRAY(drop_count, u64, 1);

int egress_filter(struct __sk_buff *skb) {
    if (skb->protocol != __constant_htons(ETH_P_IP))
        return 1;

    u32 dst = skb->remote_ip4;
    u8 *is_blocked = blocked.lookup(&dst);

    if (is_blocked) {
        u32 idx = 0;
        u64 *count = drop_count.lookup(&idx);
        if (count) (*count)++;
        return 0;  // Drop
    }

    return 1;  // Allow
}
"""

b = BPF(text=program)

# Populate blocked IPs
blocked = b["blocked"]
for ip in blocked_ips:
    parts = [int(x) for x in ip.split('.')]
    ip_int = struct.unpack("<I", bytes(parts))[0]
    blocked[ctypes.c_uint32(ip_int)] = ctypes.c_uint8(1)
    print(f"Blocking: {ip}")

fn = b.load_func("egress_filter", BPF.CGROUP_SKB)
b.attach_cgroup(cgroup_path, fn, BPF.CGROUP_INET_EGRESS)

print(f"Attached to {cgroup_path}. Ctrl+C to show stats and exit.")

try:
    while True:
        import time
        time.sleep(1)
except KeyboardInterrupt:
    pass

# Print drop count
drops = sum(b["drop_count"][0])
print(f"\nTotal dropped packets: {drops}")
```

## Exercises

1. **Port blocking**: Write a cgroup program that blocks all outgoing connections except to ports 80 and 443.

2. **Connection logging**: Use sock_ops to log all TCP connections (established and closed) for a cgroup.

3. **Bind restriction**: Create a program that only allows processes to bind to ports 8000-9000.

4. **Rate limiting setup**: Track connection count per minute. (The actual limiting would need additional logic, but track the metric.)

5. **Connect redirection**: Redirect all DNS queries (port 53) to a local DNS server at 127.0.0.1:5353.

6. **Container isolation**: Create a policy that blocks inter-container communication while allowing external traffic.
