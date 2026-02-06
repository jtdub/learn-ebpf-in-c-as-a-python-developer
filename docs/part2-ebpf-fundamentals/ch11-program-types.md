# Chapter 11: Program Types

eBPF programs are not one-size-fits-all. Each **program type** attaches to a different kernel subsystem, receives a different context struct, and has different capabilities. Choosing the right program type is the first design decision for any eBPF project.

This chapter maps out the program types you will use most often, explaining when to use each one and what data you can access.

## The Program Type Model

When you load an eBPF program, you specify its type. The type determines:

1. **Where it attaches** — which kernel hook point
2. **What context it receives** — the `ctx` parameter to your function
3. **What helpers it can call** — not all helpers work with all program types
4. **What return values mean** — `XDP_DROP` vs `TC_ACT_SHOT` vs `0`

```c
// The SEC() macro encodes the program type
SEC("xdp")              // Program type: XDP
SEC("kprobe/tcp_connect")  // Program type: kprobe
SEC("tc")               // Program type: TC classifier
SEC("cgroup/connect4")  // Program type: cgroup sock_addr
```

## Program Types Overview

| Type | Constant | Hook Point | Context | Primary Use |
|------|----------|------------|---------|-------------|
| XDP | `BPF_PROG_TYPE_XDP` | Network driver (earliest) | `xdp_md` | High-performance packet processing |
| TC | `BPF_PROG_TYPE_SCHED_CLS` | Traffic control qdisc | `__sk_buff` | Packet filtering/modification |
| Socket Filter | `BPF_PROG_TYPE_SOCKET_FILTER` | Socket | `__sk_buff` | Per-socket packet filtering |
| Kprobe | `BPF_PROG_TYPE_KPROBE` | Any kernel function | `pt_regs` | Tracing/debugging |
| Tracepoint | `BPF_PROG_TYPE_TRACEPOINT` | Predefined trace events | Event-specific | Stable tracing |
| Perf Event | `BPF_PROG_TYPE_PERF_EVENT` | Hardware/software counters | `bpf_perf_event_data` | Profiling |
| Cgroup Socket | `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` | Socket syscalls | `bpf_sock_addr` | Intercepting connect/bind |
| Sock Ops | `BPF_PROG_TYPE_SOCK_OPS` | Socket operations | `bpf_sock_ops` | Connection-level events |
| SK MSG | `BPF_PROG_TYPE_SK_MSG` | Socket messages | `sk_msg_md` | Socket-to-socket forwarding |
| LSM | `BPF_PROG_TYPE_LSM` | Security hooks | Hook-specific | Security policies |

## XDP: eXpress Data Path

XDP programs run at the **earliest possible point** in the network stack — in the network driver, before the kernel allocates an `sk_buff`. This makes XDP the fastest option for packet processing.

### Context: `struct xdp_md`

```c
struct xdp_md {
    __u32 data;         // Pointer to packet data start
    __u32 data_end;     // Pointer to packet data end
    __u32 data_meta;    // Pointer to metadata area
    __u32 ingress_ifindex;  // Interface index
    __u32 rx_queue_index;   // RX queue index
    __u32 egress_ifindex;   // Egress interface (for redirect)
};
```

### Return Values

| Value | Meaning |
|-------|---------|
| `XDP_PASS` | Pass packet to normal network stack |
| `XDP_DROP` | Drop packet immediately |
| `XDP_TX` | Send packet back out the same interface |
| `XDP_REDIRECT` | Redirect to another interface/CPU/socket |
| `XDP_ABORTED` | Error, drop and signal an error |

### Use Cases

- DDoS mitigation (drop bad packets at line rate)
- Load balancing
- Packet forwarding
- Simple firewalling

### Example

```c
SEC("xdp")
int xdp_drop_icmp(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Drop ICMP packets
    if (ip->protocol == IPPROTO_ICMP)
        return XDP_DROP;

    return XDP_PASS;
}
```

## TC: Traffic Control

TC programs attach to the Linux traffic control subsystem, running slightly later than XDP but with more features. They work on both **ingress** (incoming) and **egress** (outgoing) traffic.

### Context: `struct __sk_buff`

```c
struct __sk_buff {
    __u32 len;              // Packet length
    __u32 pkt_type;         // Packet type
    __u32 mark;             // Packet mark
    __u32 queue_mapping;    // Queue mapping
    __u32 protocol;         // Protocol
    __u32 vlan_present;     // VLAN present flag
    __u32 vlan_tci;         // VLAN TCI
    __u32 vlan_proto;       // VLAN protocol
    __u32 priority;         // Priority
    __u32 ingress_ifindex;  // Ingress interface
    __u32 ifindex;          // Interface index
    __u32 tc_index;         // TC index
    __u32 cb[5];            // Control buffer
    __u32 hash;             // Packet hash
    __u32 tc_classid;       // TC class ID
    __u32 data;             // Packet data pointer
    __u32 data_end;         // Packet data end
    __u32 napi_id;          // NAPI ID
    // ... more fields
};
```

### Return Values

| Value | Meaning |
|-------|---------|
| `TC_ACT_OK` / `TC_ACT_UNSPEC` | Continue processing |
| `TC_ACT_SHOT` | Drop packet |
| `TC_ACT_REDIRECT` | Redirect packet |
| `TC_ACT_STOLEN` | Consumed by BPF program |

### TC vs XDP

| Feature | XDP | TC |
|---------|-----|----
| Speed | Fastest (driver level) | Fast (after sk_buff allocation) |
| Egress support | Limited (TX only on same interface) | Full egress support |
| Packet modification | Direct memory access | Via helpers (`bpf_skb_store_bytes`) |
| Socket information | Not available | Available |
| Hardware offload | Yes (some NICs) | No |

### Use Cases

- Egress filtering/modification
- Container networking (CNI plugins)
- When you need socket/process context
- Packet rewriting that XDP can't do

## Kprobe: Kernel Function Tracing

Kprobes let you attach to **any kernel function** and inspect its arguments or return value. They're the most flexible tracing mechanism but also the least stable (kernel functions can change between versions).

### Context: `struct pt_regs`

The context is the CPU register state, from which you extract function arguments:

```c
// On x86_64, function arguments are in registers
// PT_REGS_PARM1(ctx) = first argument
// PT_REGS_PARM2(ctx) = second argument
// PT_REGS_RC(ctx) = return value (for kretprobes)
```

### Two Flavors

| Type | Section | When It Fires | Access |
|------|---------|--------------|--------|
| Kprobe | `SEC("kprobe/func")` | Function entry | Arguments |
| Kretprobe | `SEC("kretprobe/func")` | Function return | Return value |

### Example

```c
SEC("kprobe/tcp_connect")
int BPF_KPROBE(trace_connect, struct sock *sk) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Read destination port from sock structure
    __u16 dport;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);

    bpf_printk("PID %d connecting to port %d\n", pid, bpf_ntohs(dport));
    return 0;
}
```

!!! warning "Kprobes Are Unstable"
    Internal kernel functions can change between versions. A kprobe that works on kernel 5.15 might break on 6.1. For stable tracing, prefer tracepoints.

## Tracepoints: Stable Tracing

Tracepoints are predefined instrumentation points in the kernel with stable interfaces. Unlike kprobes, they're guaranteed to exist (though they can be deprecated).

### Finding Tracepoints

```bash
# List all tracepoints
sudo ls /sys/kernel/debug/tracing/events/

# List syscall tracepoints
sudo ls /sys/kernel/debug/tracing/events/syscalls/

# See tracepoint format (what fields are available)
sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_connect/format
```

### Context

Each tracepoint has its own context struct matching its format:

```c
// For syscalls/sys_enter_connect
struct trace_event_raw_sys_enter {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    long id;           // Syscall number
    unsigned long args[6];  // Syscall arguments
};
```

### Example

```c
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect_enter(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("PID %d called connect()\n", pid);
    return 0;
}
```

## Cgroup Programs: Intercepting Socket Operations

Cgroup-attached programs intercept socket operations for processes in a cgroup. This is how container runtimes implement network policies.

### `BPF_PROG_TYPE_CGROUP_SOCK_ADDR`

Intercepts `connect()`, `bind()`, `sendmsg()`, and `getpeername()`:

| Section | Operation | Can Modify |
|---------|-----------|------------|
| `cgroup/connect4` | IPv4 connect | Destination address/port |
| `cgroup/connect6` | IPv6 connect | Destination address/port |
| `cgroup/bind4` | IPv4 bind | Local address/port |
| `cgroup/bind6` | IPv6 bind | Local address/port |
| `cgroup/sendmsg4` | IPv4 UDP sendmsg | Destination address/port |
| `cgroup/sendmsg6` | IPv6 UDP sendmsg | Destination address/port |

### Context: `struct bpf_sock_addr`

```c
struct bpf_sock_addr {
    __u32 user_family;   // Address family (AF_INET, AF_INET6)
    __u32 user_ip4;      // User-provided IPv4 address
    __u32 user_ip6[4];   // User-provided IPv6 address
    __u32 user_port;     // User-provided port (network byte order)
    __u32 family;        // Protocol family
    __u32 type;          // Socket type
    __u32 protocol;      // Protocol
    // ... more fields
};
```

### Use Cases

- Transparent proxying (redirect connections)
- Network policies in containers
- Service mesh without sidecars

### Example: Redirect All Connections to Port 80 → 8080

```c
SEC("cgroup/connect4")
int redirect_http(struct bpf_sock_addr *ctx) {
    // Check if connecting to port 80
    if (ctx->user_port == bpf_htons(80)) {
        // Redirect to port 8080
        ctx->user_port = bpf_htons(8080);
    }
    return 1;  // Allow connection
}
```

## Sock Ops: Connection Events

`BPF_PROG_TYPE_SOCK_OPS` fires on socket-level events — connection establishment, state changes, etc.

### Context: `struct bpf_sock_ops`

```c
struct bpf_sock_ops {
    __u32 op;            // Operation type
    __u32 family;        // Address family
    __u32 remote_ip4;    // Remote IPv4
    __u32 local_ip4;     // Local IPv4
    __u32 remote_port;   // Remote port
    __u32 local_port;    // Local port
    // ... many more fields
};
```

### Operations (ctx->op values)

| Operation | When |
|-----------|------|
| `BPF_SOCK_OPS_TCP_CONNECT_CB` | Active connection established |
| `BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB` | Passive connection established |
| `BPF_SOCK_OPS_STATE_CB` | Socket state change |
| `BPF_SOCK_OPS_RTT_CB` | RTT measurement |

### Use Cases

- Building socket lookup maps for sk_msg programs
- Collecting connection metrics
- Modifying TCP parameters

## SK_MSG: Socket-to-Socket Forwarding

`BPF_PROG_TYPE_SK_MSG` programs intercept messages on a socket and can redirect them to another socket — enabling **kernel-level proxying** without copying data to userspace.

This is how service meshes achieve fast socket redirection.

### Context: `struct sk_msg_md`

```c
struct sk_msg_md {
    __u32 data;          // Message data start
    __u32 data_end;      // Message data end
    __u32 family;        // Address family
    __u32 remote_ip4;    // Remote IPv4
    __u32 local_ip4;     // Local IPv4
    __u32 remote_port;   // Remote port
    __u32 local_port;    // Local port
    __u32 size;          // Message size
    // ...
};
```

### Return Values

| Value | Meaning |
|-------|---------|
| `SK_PASS` | Continue normal delivery |
| `SK_DROP` | Drop the message |

With `bpf_msg_redirect_hash()` or `bpf_msg_redirect_map()`, you can redirect to another socket.

## Choosing the Right Program Type

### For Packet Processing

| Need | Program Type |
|------|-------------|
| Highest performance, simple filtering | XDP |
| Egress traffic | TC |
| Per-socket filtering | Socket Filter |
| Modify packets with full context | TC |

### For Tracing

| Need | Program Type |
|------|-------------|
| Any kernel function | Kprobe |
| Stable, supported events | Tracepoint |
| Performance counters | Perf Event |

### For Networking Control

| Need | Program Type |
|------|-------------|
| Intercept connect/bind | Cgroup sock_addr |
| Connection-level events | Sock Ops |
| Socket-to-socket redirect | SK MSG |
| Security decisions | LSM |

## Exercises

1. **Program type identification**: For each scenario, identify the best program type:
    - Drop packets from a specific IP at line rate
    - Log all `open()` syscalls with filenames
    - Redirect all HTTP connections to a local proxy
    - Count bytes sent per process

2. **Context exploration**: Write a minimal program for XDP, TC, and kprobe. Print the size of each context struct.

3. **Tracepoint discovery**: Use `/sys/kernel/debug/tracing/events` to find a tracepoint for file opens. Write a program that traces it.

4. **Return value meaning**: Create a table showing what return value 0 means for each program type (pass? drop? error?).

5. **Helper availability**: Using `bpftool feature probe` or documentation, identify which helpers are available for XDP vs TC vs kprobe programs.
