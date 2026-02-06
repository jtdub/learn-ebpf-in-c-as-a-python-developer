# Chapter 26: Tracing with Kprobes

Kprobes (kernel probes) let you attach an eBPF program to **any kernel function**. When that function is called, your program runs and can inspect the function's arguments, the calling process, timestamps, and more. This is the most flexible tracing mechanism in the eBPF toolkit.

If you have used Python decorators to wrap functions and log their arguments, kprobes are the kernel equivalent -- except you are wrapping functions you did not write, in code you do not own, inside the kernel.

## How Kprobes Work

When you attach a kprobe to a kernel function, the kernel dynamically patches the function's first instruction with a breakpoint. When execution hits that breakpoint, the kernel runs your eBPF program, then continues with the original function.

```
Normal execution:          With kprobe attached:

tcp_connect()              tcp_connect()
  │                          │
  ├─ do work                 ├─ BREAKPOINT → run your eBPF program
  ├─ ...                     ├─ do work
  └─ return                  ├─ ...
                             └─ return
```

There are two types:

| Type | When It Fires | What You Can Access |
|------|--------------|-------------------|
| **kprobe** | At function **entry** | Function arguments (via `struct pt_regs`) |
| **kretprobe** | At function **return** | Return value (via `struct pt_regs`) |

!!! warning "Kprobes Are Unstable"
    Kprobes attach to internal kernel functions. These functions can be renamed, removed, or have their signatures changed between kernel versions. A kprobe that works on kernel 5.15 might break on kernel 6.1. For stable instrumentation, use tracepoints (Chapter 27). Kprobes are best for debugging and short-lived tools.

## Accessing Function Arguments

When your kprobe fires, you receive a pointer to `struct pt_regs`, which contains the CPU register state at the time the function was called. On x86_64, function arguments are passed in registers:

| Argument | Register | `pt_regs` field |
|----------|----------|-----------------|
| 1st | `rdi` | `ctx->di` |
| 2nd | `rsi` | `ctx->si` |
| 3rd | `rdx` | `ctx->dx` |
| 4th | `rcx` | `ctx->cx` |
| 5th | `r8` | `ctx->r8` |
| 6th | `r9` | `ctx->r9` |

!!! note "Architecture Dependency"
    The register layout is architecture-specific. The table above is for x86_64. On ARM64, arguments are in `x0` through `x7`. BCC provides `PT_REGS_PARM1(ctx)` through `PT_REGS_PARM6(ctx)` macros that work across architectures.

### Reading Kernel Memory Safely

Function arguments are often pointers to kernel data structures. You cannot dereference kernel pointers directly in eBPF -- the verifier will reject it. Instead, use `bpf_probe_read_kernel()`:

```c
// WRONG -- verifier rejects direct dereference of kernel pointer
struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
u16 port = sk->sk_dport;  // REJECTED

// RIGHT -- use bpf_probe_read_kernel
struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
u16 port;
bpf_probe_read_kernel(&port, sizeof(port), &sk->sk_dport);
```

Think of `bpf_probe_read_kernel()` like Python's `ctypes.memmove()` -- it copies bytes from a kernel address into your local variable, with safety checks.

## Key Kernel Functions for Network Observability

These are the kernel functions you will probe most often when tracing network activity:

| Function | What It Does | Useful Arguments |
|----------|-------------|-----------------|
| `tcp_connect` | Initiates a TCP connection (SYN) | `struct sock *sk` -- the socket |
| `inet_csk_accept` | Accepts an incoming TCP connection | Returns `struct sock *` |
| `tcp_sendmsg` | Sends data over TCP | `struct sock *sk`, `struct msghdr *msg`, `size_t size` |
| `tcp_recvmsg` | Receives data over TCP | `struct sock *sk`, `struct msghdr *msg`, `size_t len` |
| `tcp_close` | Closes a TCP connection | `struct sock *sk` |
| `tcp_retransmit_skb` | Retransmits a TCP segment | `struct sock *sk`, `struct sk_buff *skb` |

From `struct sock`, you can extract source/destination addresses, ports, the connection state, and more.

## Complete Example: Trace All TCP Connections

Let's build a tool that logs every outgoing TCP connection with the PID, process name, and source/destination addresses. This is similar to what tools like `tcpconnect` from BCC-tools do.

=== "BCC (Python)"

    ```python
    #!/usr/bin/env python3
    """Trace outgoing TCP connections with PID, comm, and addresses."""

    from bcc import BPF
    from socket import inet_ntop, AF_INET
    import struct

    program = r"""
    #include <uapi/linux/ptrace.h>
    #include <net/sock.h>
    #include <bcc/proto.h>

    struct event_t {
        u32 pid;
        u32 uid;
        u16 sport;
        u16 dport;
        u32 saddr;
        u32 daddr;
        char comm[16];
    };

    BPF_PERF_OUTPUT(events);

    int trace_tcp_connect(struct pt_regs *ctx, struct sock *sk) {
        struct event_t event = {};

        // Get process info
        u64 pid_tgid = bpf_get_current_pid_tgid();
        event.pid = pid_tgid >> 32;
        event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        bpf_get_current_comm(&event.comm, sizeof(event.comm));

        // Read socket fields
        event.saddr = sk->__sk_common.skc_rcv_saddr;
        event.daddr = sk->__sk_common.skc_daddr;
        event.sport = sk->__sk_common.skc_num;
        event.dport = sk->__sk_common.skc_dport;

        // dport is in network byte order -- convert to host
        event.dport = ntohs(event.dport);

        events.perf_submit(ctx, &event, sizeof(event));
        return 0;
    }
    """

    b = BPF(text=program)
    b.attach_kprobe(event="tcp_connect", fn_name="trace_tcp_connect")

    print("%-8s %-6s %-6s %-16s %-22s %-22s" % (
        "TIME", "PID", "UID", "COMM", "SOURCE", "DESTINATION"))

    def print_event(cpu, data, size):
        event = b["events"].event(data)
        src = "%s:%d" % (inet_ntop(AF_INET, struct.pack("I", event.saddr)),
                         event.sport)
        dst = "%s:%d" % (inet_ntop(AF_INET, struct.pack("I", event.daddr)),
                         event.dport)
        print("%-8s %-6d %-6d %-16s %-22s %-22s" % (
            BPF.monotonic_print(), event.pid, event.uid,
            event.comm.decode('utf-8', 'replace'), src, dst))

    b["events"].open_perf_buffer(print_event)

    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nDone.")
    ```

    Run it with `sudo python3 tcp_connect_tracer.py` and make a connection from another terminal:

    ```bash
    curl http://example.com
    ```

    You will see output like:

    ```
    TIME     PID    UID    COMM             SOURCE                 DESTINATION
    0.000    14523  1000   curl             10.0.2.15:54312        93.184.216.34:80
    ```

=== "libbpf (C)"

    **eBPF program (`tcp_connect.bpf.c`):**

    ```c
    #include "vmlinux.h"
    #include <bpf/bpf_helpers.h>
    #include <bpf/bpf_core_read.h>
    #include <bpf/bpf_endian.h>

    struct event_t {
        __u32 pid;
        __u32 uid;
        __u16 sport;
        __u16 dport;
        __u32 saddr;
        __u32 daddr;
        char comm[16];
    };

    struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 256 * 1024);  /* 256 KB */
    } events SEC(".maps");

    SEC("kprobe/tcp_connect")
    int BPF_KPROBE(trace_tcp_connect, struct sock *sk) {
        struct event_t *event;

        event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
        if (!event)
            return 0;

        /* Process info */
        __u64 pid_tgid = bpf_get_current_pid_tgid();
        event->pid = pid_tgid >> 32;
        event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        bpf_get_current_comm(&event->comm, sizeof(event->comm));

        /* Socket info -- use CO-RE to read kernel struct fields */
        event->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        event->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        event->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
        event->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

        bpf_ringbuf_submit(event, 0);
        return 0;
    }

    char LICENSE[] SEC("license") = "GPL";
    ```

    **Userspace loader (`tcp_connect.c`):**

    ```c
    #include <stdio.h>
    #include <signal.h>
    #include <unistd.h>
    #include <arpa/inet.h>
    #include <bpf/libbpf.h>
    #include "tcp_connect.skel.h"

    struct event_t {
        __u32 pid;
        __u32 uid;
        __u16 sport;
        __u16 dport;
        __u32 saddr;
        __u32 daddr;
        char comm[16];
    };

    static volatile bool running = true;

    static void sig_handler(int sig) {
        running = false;
    }

    static int handle_event(void *ctx, void *data, size_t data_sz) {
        const struct event_t *event = data;
        char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &event->saddr, src, sizeof(src));
        inet_ntop(AF_INET, &event->daddr, dst, sizeof(dst));

        printf("%-6d %-6d %-16s %s:%-6d -> %s:%-6d\n",
               event->pid, event->uid, event->comm,
               src, event->sport, dst, event->dport);
        return 0;
    }

    int main(void) {
        struct tcp_connect_bpf *skel;
        struct ring_buffer *rb;

        signal(SIGINT, sig_handler);
        signal(SIGTERM, sig_handler);

        skel = tcp_connect_bpf__open_and_load();
        if (!skel) {
            fprintf(stderr, "Failed to open and load BPF skeleton\n");
            return 1;
        }

        if (tcp_connect_bpf__attach(skel)) {
            fprintf(stderr, "Failed to attach BPF programs\n");
            goto cleanup;
        }

        rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
                              handle_event, NULL, NULL);
        if (!rb) {
            fprintf(stderr, "Failed to create ring buffer\n");
            goto cleanup;
        }

        printf("%-6s %-6s %-16s %-22s    %-22s\n",
               "PID", "UID", "COMM", "SOURCE", "DESTINATION");

        while (running) {
            int err = ring_buffer__poll(rb, 100 /* timeout ms */);
            if (err == -EINTR)
                break;
        }

        ring_buffer__free(rb);
    cleanup:
        tcp_connect_bpf__destroy(skel);
        return 0;
    }
    ```

!!! tip "BCC Auto-Reads Struct Fields"
    Notice that in the BCC version, you can write `sk->__sk_common.skc_daddr` directly. BCC rewrites this to `bpf_probe_read_kernel()` calls behind the scenes. In libbpf, you must use `BPF_CORE_READ()` explicitly. This is one of BCC's conveniences for prototyping, and one reason it is slower to compile.

## Using Kretprobes for Return Values

A kretprobe fires when the function returns. This is useful for capturing return values, measuring function duration, or correlating entry arguments with the outcome.

Here is a pattern for measuring function latency -- store the entry timestamp in a map, then compute the difference at return:

```c
/* Store entry timestamp keyed by thread ID */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} start SEC(".maps");

SEC("kprobe/tcp_connect")
int BPF_KPROBE(trace_connect_entry, struct sock *sk) {
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &tid, &ts, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_connect")
int BPF_KRETPROBE(trace_connect_return, int ret) {
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u64 *tsp = bpf_map_lookup_elem(&start, &tid);
    if (!tsp)
        return 0;  /* missed entry */

    __u64 duration_ns = bpf_ktime_get_ns() - *tsp;
    bpf_map_delete_elem(&start, &tid);

    /* duration_ns now contains the function's execution time */
    bpf_printk("tcp_connect took %llu ns (ret=%d)", duration_ns, ret);
    return 0;
}
```

!!! note "The Entry/Return Pattern"
    This pattern of storing state at function entry and computing at return is extremely common in eBPF tracing. You will use it for latency measurement, correlating arguments with return values, and building call graphs. The map key is typically the thread ID (`bpf_get_current_pid_tgid() & 0xFFFFFFFF`) because the same thread that enters a function will return from it.

## Finding Kernel Functions to Probe

You can discover available kernel functions to probe:

```bash
# List all kernel functions available for kprobes
sudo cat /sys/kernel/debug/tracing/available_filter_functions | head -20

# Search for specific functions
sudo cat /sys/kernel/debug/tracing/available_filter_functions | grep tcp_connect

# Use bpftool to find functions with BTF info
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c | grep "tcp_connect"
```

In Python terms, this is like using `dir()` and `inspect.signature()` to discover what functions exist and what arguments they take.

## Common Pitfalls

**1. Function was inlined.** If the compiler inlined a function, it has no entry point for a kprobe. You will get an error like `Failed to attach kprobe`. Check `available_filter_functions` to verify the function exists.

**2. Wrong argument types.** If you cast `PT_REGS_PARM1(ctx)` to the wrong struct type, you will read garbage data. Always check the kernel source for the function signature.

**3. Forgotten NULL checks.** Every `bpf_map_lookup_elem()` can return NULL. The verifier requires you to check before using the pointer.

**4. Network byte order confusion.** Ports in `struct sock` are in network byte order (big-endian). Always use `ntohs()` or `bpf_ntohs()` before displaying them.

## Exercises

1. **Trace TCP accepts.** Attach a kretprobe to `inet_csk_accept` to trace incoming TCP connections. Print the remote address and port for each accepted connection. Hint: the return value is a `struct sock *` -- read the address fields from it.

2. **Measure `tcp_sendmsg` latency.** Use the entry/return pattern to measure how long each `tcp_sendmsg` call takes. Store the duration and print it. Filter to only show calls that take longer than 1 millisecond.

3. **Count connections per process.** Create a BPF hash map keyed by PID that counts how many times each process calls `tcp_connect`. Print the top 10 processes by connection count when the user presses Ctrl-C.

4. **Trace DNS lookups.** Attach a kprobe to `udp_sendmsg` and filter for packets going to port 53 (DNS). Extract and display the destination address. This shows you how to combine kprobes with packet-level filtering.

5. **Build a retransmit tracker.** Attach a kprobe to `tcp_retransmit_skb` and log every TCP retransmission with the source/destination address and port. Retransmissions are a key signal for network health issues.
