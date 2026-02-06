# Part 3: Packet Interception & Manipulation

This is the core of the guide. Parts 1 and 2 gave you the language and the platform. Part 3 is where you use them together to intercept, inspect, modify, and redirect network traffic inside the Linux kernel.

If you came to eBPF because you want to understand how tools like Cilium, Istio's sidecar-free mode, or Cloudflare's DDoS mitigation work, this is the part that explains the mechanics. Every proxy, load balancer, firewall, and traffic-shaping tool built on eBPF uses the techniques covered in these eight chapters.

## The Linux Networking Stack and eBPF Hook Points

When a packet arrives at a network interface or when an application makes a network syscall, it passes through a series of stages in the Linux kernel. eBPF lets you attach programs at specific points in this pipeline. Here is the full picture:

```
                        ┌─────────────────────────────────────┐
                        │          USERSPACE APPLICATION       │
                        │   socket(), connect(), sendmsg()...  │
                        └──────────┬──────────────┬────────────┘
                                   │              ▲
                          syscall  │              │  data delivered
                                   ▼              │  to application
                        ┌──────────────────────────────────────┐
                        │         CGROUP/SOCK_ADDR HOOKS       │
                        │  (intercept connect, bind, sendmsg)  │
                        │  BPF_PROG_TYPE_CGROUP_SOCK_ADDR      │
                        │  ──── Chapter 19 ────                │
                        └──────────┬──────────────┬────────────┘
                                   │              ▲
                                   ▼              │
                        ┌──────────────────────────────────────┐
                        │         SOCKET LAYER                 │
                        │  sock_ops, sk_msg, socket filters    │
                        │  BPF_PROG_TYPE_SOCK_OPS              │
                        │  BPF_PROG_TYPE_SK_MSG                │
                        │  BPF_PROG_TYPE_SOCKET_FILTER         │
                        │  ──── Chapters 24-25 ────            │
                        └──────────┬──────────────┬────────────┘
                                   │              ▲
                                   ▼              │
                        ┌──────────────────────────────────────┐
                        │         TCP/IP STACK                 │
                        │   (routing, connection tracking,     │
                        │    fragmentation, reassembly)        │
                        └──────────┬──────────────┬────────────┘
                                   │              ▲
                                   ▼              │
           EGRESS                  │              │           INGRESS
   ┌───────────────────────────────┘              └──────────────────────────┐
   │                                                                        │
   ▼                                                                        │
┌──────────────────────┐                                ┌───────────────────────┐
│   TC EGRESS          │                                │   TC INGRESS          │
│   (outgoing packets) │                                │   (incoming packets)  │
│   BPF_PROG_TYPE_     │                                │   BPF_PROG_TYPE_      │
│   SCHED_CLS          │                                │   SCHED_CLS           │
│   ── Chapter 20 ──   │                                │   ── Chapter 20 ──    │
└──────┬───────────────┘                                └───────────────────┬───┘
       │                                                                    ▲
       ▼                                                                    │
┌──────────────────────┐                                ┌───────────────────────┐
│   DRIVER / NIC       │                                │   DRIVER / NIC        │
│                      │──────── WIRE ─────────────────▶│                       │
└──────────────────────┘                                └───────────────────┬───┘
                                                                            ▲
                                                        ┌───────────────────────┐
                                                        │   XDP                 │
                                                        │   (earliest hook,     │
                                                        │    before sk_buff)    │
                                                        │   BPF_PROG_TYPE_XDP   │
                                                        │   ── Chapter 21 ──    │
                                                        └───────────────────────┘
```

!!! note "Reading the Diagram"
    Ingress (incoming) traffic flows from the bottom up: NIC --> XDP --> TC ingress --> TCP/IP stack --> socket layer --> application. Egress (outgoing) traffic flows from the top down: application --> cgroup hooks --> TCP/IP stack --> TC egress --> NIC. eBPF hooks exist at nearly every stage. You choose which hook point based on what you need to do.

## Hook Points Summary

Each hook point gives you a different **context struct**, different **capabilities**, and different **performance characteristics**:

| Hook Point | Program Type | Context Struct | Can Modify? | Can Drop? | Can Redirect? | Speed |
|---|---|---|---|---|---|---|
| **XDP** | `BPF_PROG_TYPE_XDP` | `struct xdp_md` | Yes (raw bytes) | Yes (`XDP_DROP`) | Yes (`XDP_REDIRECT`) | Fastest |
| **TC ingress/egress** | `BPF_PROG_TYPE_SCHED_CLS` | `struct __sk_buff` | Yes (helpers) | Yes (`TC_ACT_SHOT`) | Yes (`TC_ACT_REDIRECT`) | Fast |
| **cgroup/sock_addr** | `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` | `struct bpf_sock_addr` | Yes (addr/port) | Yes (return 0) | Implicit (rewrite dest) | N/A (syscall-level) |
| **sock_ops** | `BPF_PROG_TYPE_SOCK_OPS` | `struct bpf_sock_ops` | Limited | No | No (but sets up maps) | N/A (event-driven) |
| **sk_msg** | `BPF_PROG_TYPE_SK_MSG` | `struct sk_msg_md` | No | Yes (drop msg) | Yes (redirect to socket) | Fast (no network stack) |
| **socket filter** | `BPF_PROG_TYPE_SOCKET_FILTER` | `struct __sk_buff` | No | Yes (return 0) | No | Moderate |

## How Python Developers Should Think About This

In Python, networking feels like a single abstraction:

```python
import requests
response = requests.get("http://example.com")  # Magic happens
```

Under the hood, that one line triggers dozens of kernel operations: DNS resolution, socket creation, TCP handshake, packet construction, routing, checksum calculation, driver transmission, and the reverse for each response packet. eBPF lets you insert your code at specific points in that pipeline.

Think of it like Python decorators for the kernel's networking functions:

=== "Python Mental Model"

    ```python
    # This is NOT real code — it's a mental model
    @ebpf_hook("xdp")          # Earliest possible: raw packet from NIC
    def inspect_packet(ctx):
        if is_malicious(ctx.data):
            return XDP_DROP      # Never enters the kernel
        return XDP_PASS

    @ebpf_hook("cgroup/connect4")  # When app calls connect()
    def redirect_connection(ctx):
        if ctx.user_port == 80:
            ctx.user_ip4 = new_ip  # Silently redirect
        return 1                    # Allow (modified) connection

    @ebpf_hook("tc/egress")       # Packet leaving the machine
    def rewrite_header(ctx):
        change_dest_ip(ctx, new_addr)
        fix_checksum(ctx)
        return TC_ACT_OK
    ```

=== "Reality (C)"

    ```c
    // XDP program — we will build this in Chapter 21
    SEC("xdp")
    int inspect_packet(struct xdp_md *ctx) {
        void *data = (void *)(long)ctx->data;
        void *data_end = (void *)(long)ctx->data_end;
        // Parse and decide...
        return XDP_PASS;
    }

    // Cgroup hook — Chapter 19
    SEC("cgroup/connect4")
    int redirect_connection(struct bpf_sock_addr *ctx) {
        if (ctx->user_port == bpf_htons(80)) {
            ctx->user_ip4 = bpf_htonl(0x7f000001); // redirect to 127.0.0.1
        }
        return 1;
    }

    // TC program — Chapter 20
    SEC("tc")
    int rewrite_header(struct __sk_buff *skb) {
        // Parse packet, modify, fix checksums...
        return TC_ACT_OK;
    }
    ```

## What This Part Covers

| Chapter | Topic | What You'll Build |
|---------|-------|-------------------|
| [Ch 18: Socket Syscalls](ch18-socket-syscalls.md) | How networking syscalls work at the kernel level | Mental model of the connect() journey |
| [Ch 19: Cgroup Hooks](ch19-cgroup-hooks.md) | Intercepting connect(), bind(), sendmsg() before they execute | Connection logger, connection redirector |
| [Ch 20: TC Programs](ch20-tc-programs.md) | Traffic Control hooks for packet inspection at ingress/egress | Ingress packet logger |
| [Ch 21: XDP Programs](ch21-xdp-programs.md) | Fastest hook point, before sk_buff allocation | IP blocker, protocol counter |
| [Ch 22: Packet Parsing](ch22-packet-parsing.md) | Walking packet headers layer by layer with bounds checks | Full TCP packet parser |
| [Ch 23: Header Rewriting](ch23-header-rewriting.md) | Modifying IP/port and recalculating checksums | Destination rewriter with checksums |
| [Ch 24: Traffic Redirection](ch24-traffic-redirection.md) | Moving packets between interfaces and sockets | Socket-level traffic redirect |
| [Ch 25: Socket Filtering](ch25-socket-filtering.md) | Filtering packets before they reach userspace | TCP SYN filter on raw socket |

## Prerequisites

Before starting Part 3, you should be comfortable with:

- **C structs and pointer arithmetic** (Part 1, Chapters 2-3) — you will be casting pointers to packet headers constantly
- **Bitwise operations** (Part 1, Chapter 6) — protocol flags, header fields, and masks are everywhere
- **Networking structs** (Part 1, Chapter 8) — `struct iphdr`, `struct tcphdr`, `struct ethhdr` are your daily tools
- **BPF maps and helpers** (Part 2, Chapters 12-13) — every program in Part 3 uses maps to communicate with userspace
- **The verifier** (Part 2, Chapter 14) — the verifier is the primary source of frustration in packet processing programs, and understanding its rules will save you hours

!!! warning "Kernel Version Requirements"
    The features in Part 3 have been added across many kernel versions. The examples in this guide target **Linux 5.15+**, which is the minimum for full support of all program types and helpers discussed. If you are running an older kernel, some features may be unavailable. Check your kernel version with `uname -r`.

!!! tip "Development Environment"
    All examples in Part 3 can be tested in a virtual machine. We strongly recommend using a VM (Vagrant, multipass, or a cloud instance) rather than your host machine, since eBPF programs that modify network traffic can lock you out of a remote session if something goes wrong.

## The Skills You'll Have After Part 3

By the end of these eight chapters, you will be able to:

1. **Intercept** any network connection at the syscall level and decide whether to allow, block, or redirect it
2. **Inspect** packets at any layer (Ethernet, IP, TCP/UDP) from the earliest possible hook point
3. **Parse** packet headers safely, satisfying the eBPF verifier's bounds-checking requirements
4. **Rewrite** packet headers (source/destination IP, ports) with correct checksum recalculation
5. **Redirect** traffic between network interfaces, CPUs, or directly between sockets
6. **Filter** packets before they reach userspace applications

These are the same primitives that production networking tools use. The difference between your Chapter 25 exercise and a production service mesh is scale and polish, not fundamentally different techniques.

Let's begin with [Chapter 18: Socket Syscalls](ch18-socket-syscalls.md) -- understanding the system calls that create and manage network connections.
