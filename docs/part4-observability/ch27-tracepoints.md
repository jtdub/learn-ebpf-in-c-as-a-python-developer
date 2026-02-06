# Chapter 27: Tracepoints

Tracepoints are stable kernel instrumentation points — predefined hooks that kernel developers maintain across versions. Unlike kprobes (which attach to any function), tracepoints have stable interfaces, making them the preferred choice for production observability tools.

## Kprobes vs Tracepoints

| Aspect | Kprobes | Tracepoints |
|--------|---------|-------------|
| Coverage | Any kernel function | Predefined points only |
| Stability | May break between versions | Stable API |
| Performance | Slightly higher overhead | Optimized |
| Arguments | Raw function args | Structured, documented |
| Availability | Always | Only where defined |

**Rule of thumb**: Use tracepoints when available, fall back to kprobes when not.

## Finding Tracepoints

### List All Tracepoints

```bash
# All available tracepoints
sudo cat /sys/kernel/debug/tracing/available_events

# Or with perf
perf list tracepoint
```

### Explore by Category

```bash
# List categories
ls /sys/kernel/debug/tracing/events/

# Example categories:
# - syscalls/       System calls
# - sched/          Scheduler events
# - net/            Networking
# - block/          Block I/O
# - irq/            Interrupts
# - tcp/            TCP events
# - xdp/            XDP events
```

### Get Tracepoint Format

```bash
# See arguments for a tracepoint
cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
```

Output:

```
name: sys_enter_openat
ID: 629
format:
    field:unsigned short common_type;       offset:0;  size:2; signed:0;
    field:unsigned char common_flags;       offset:2;  size:1; signed:0;
    field:unsigned char common_preempt_count; offset:3; size:1; signed:0;
    field:int common_pid;                   offset:4;  size:4; signed:1;

    field:int __syscall_nr;                 offset:8;  size:4; signed:1;
    field:int dfd;                          offset:16; size:8; signed:0;
    field:const char * filename;            offset:24; size:8; signed:0;
    field:int flags;                        offset:32; size:8; signed:0;
    field:umode_t mode;                     offset:40; size:8; signed:0;

print fmt: "dfd: 0x%08lx, filename: 0x%08lx, flags: 0x%08lx, mode: 0x%08lx"
```

## Using Tracepoints in BCC

### Basic Pattern

```python
#!/usr/bin/env python3
from bcc import BPF

program = r"""
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    bpf_trace_printk("openat: %s\n", args->filename);
    return 0;
}
"""

b = BPF(text=program)
print("Tracing openat... Ctrl+C to exit")
b.trace_print()
```

The `args` pointer gives access to tracepoint fields.

### Accessing Arguments

```python
program = r"""
#include <linux/sched.h>

struct data_t {
    u32 pid;
    char comm[16];
    char filename[256];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename),
                            args->filename);

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""
```

## Using Tracepoints in libbpf

### SEC Naming Convention

```c
// Format: tp/<category>/<tracepoint_name>
SEC("tp/syscalls/sys_enter_openat")
SEC("tp/sched/sched_process_exec")
SEC("tp/net/netif_rx")
```

### Defining Context Structures

For libbpf, define the expected arguments:

```c
// From: /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
struct trace_event_raw_sys_enter_openat {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    long dfd;
    const char *filename;
    long flags;
    long mode;
};

SEC("tp/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter_openat *ctx) {
    bpf_printk("openat dfd=%d flags=%ld\n", ctx->dfd, ctx->flags);
    return 0;
}
```

### Using vmlinux.h

With BTF, kernel provides struct definitions:

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx) {
    // Access ctx->filename, ctx->pid, etc.
    bpf_printk("exec: pid=%d\n", ctx->pid);
    return 0;
}
```

## Common Tracepoint Categories

### Syscalls

Every syscall has entry and exit tracepoints:

```c
// Entry: has arguments
SEC("tp/syscalls/sys_enter_read")
int trace_read_enter(struct trace_event_raw_sys_enter *ctx) {
    // ctx->args[0] = fd
    // ctx->args[1] = buf
    // ctx->args[2] = count
    return 0;
}

// Exit: has return value
SEC("tp/syscalls/sys_exit_read")
int trace_read_exit(struct trace_event_raw_sys_exit *ctx) {
    // ctx->ret = return value
    return 0;
}
```

### Scheduler

```c
// Process fork
SEC("tp/sched/sched_process_fork")
int trace_fork(struct trace_event_raw_sched_process_fork *ctx) {
    bpf_printk("fork: parent=%d child=%d\n",
               ctx->parent_pid, ctx->child_pid);
    return 0;
}

// Process exit
SEC("tp/sched/sched_process_exit")
int trace_exit(struct trace_event_raw_sched_process_template *ctx) {
    bpf_printk("exit: pid=%d comm=%s\n", ctx->pid, ctx->comm);
    return 0;
}

// Context switch
SEC("tp/sched/sched_switch")
int trace_switch(struct trace_event_raw_sched_switch *ctx) {
    bpf_printk("switch: %s -> %s\n", ctx->prev_comm, ctx->next_comm);
    return 0;
}
```

### Block I/O

```c
SEC("tp/block/block_rq_issue")
int trace_block_rq(struct trace_event_raw_block_rq *ctx) {
    bpf_printk("block I/O: dev=%d sector=%llu bytes=%u\n",
               ctx->dev, ctx->sector, ctx->bytes);
    return 0;
}
```

### Networking

```c
SEC("tp/net/netif_rx")
int trace_netif_rx(struct trace_event_raw_net_dev_template *ctx) {
    bpf_printk("netif_rx: %s len=%u\n", ctx->name, ctx->len);
    return 0;
}

SEC("tp/tcp/tcp_retransmit_skb")
int trace_tcp_retrans(struct trace_event_raw_tcp_event_sk_skb *ctx) {
    bpf_printk("TCP retransmit\n");
    return 0;
}
```

### XDP

```c
SEC("tp/xdp/xdp_exception")
int trace_xdp_exception(struct trace_event_raw_xdp_exception *ctx) {
    bpf_printk("XDP exception: act=%d ifindex=%d\n",
               ctx->act, ctx->ifindex);
    return 0;
}
```

## Raw Tracepoints

Raw tracepoints have lower overhead but less convenient argument access:

```c
SEC("raw_tp/sched_process_exec")
int raw_trace_exec(struct bpf_raw_tracepoint_args *ctx) {
    // Arguments are untyped
    struct task_struct *task = (struct task_struct *)ctx->args[0];
    // Need to use BPF_CORE_READ for safety
    return 0;
}
```

## Example: File Access Tracer

```python
#!/usr/bin/env python3
from bcc import BPF
import ctypes as ct

program = r"""
#include <linux/sched.h>

struct event_t {
    u32 pid;
    u32 uid;
    char comm[16];
    char filename[256];
    int flags;
    int ret;
};

BPF_HASH(active, u64, struct event_t);
BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct event_t event = {};
    u64 id = bpf_get_current_pid_tgid();

    event.pid = id >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.flags = args->flags;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename),
                            args->filename);

    active.update(&id, &event);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_openat) {
    u64 id = bpf_get_current_pid_tgid();
    struct event_t *event = active.lookup(&id);
    if (!event)
        return 0;

    event->ret = args->ret;
    events.perf_submit(args, event, sizeof(*event));
    active.delete(&id);
    return 0;
}
"""

class Event(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("uid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("filename", ct.c_char * 256),
        ("flags", ct.c_int32),
        ("ret", ct.c_int32),
    ]

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Event)).contents
    flags_str = ""
    if event.flags & 0o100:
        flags_str = "O_CREAT"
    print(f"{event.comm.decode():16} {event.pid:6} {event.filename.decode()[:50]:50} "
          f"fd={event.ret} {flags_str}")

b = BPF(text=program)
b["events"].open_perf_buffer(print_event)

print(f"{'COMM':16} {'PID':>6} {'FILENAME':50} RESULT")
while True:
    b.perf_buffer_poll()
```

## Example: Network Connection Tracker

```c
// Using libbpf
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct event {
    __u32 pid;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tp/sock/inet_sock_set_state")
int trace_connect(struct trace_event_raw_inet_sock_set_state *ctx) {
    // Only trace new connections (to ESTABLISHED)
    if (ctx->newstate != TCP_ESTABLISHED)
        return 0;

    // Only outgoing connections (from SYN_SENT)
    if (ctx->oldstate != TCP_SYN_SENT)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->saddr = ctx->saddr[0];  // For IPv4
    e->daddr = ctx->daddr[0];
    e->sport = ctx->sport;
    e->dport = ctx->dport;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

## BTF-Enabled Tracepoints

With BTF (BPF Type Format), you get type-safe access:

```c
SEC("tp_btf/sched_process_exec")
int BPF_PROG(trace_exec_btf, struct task_struct *p,
             pid_t old_pid, struct linux_binprm *bprm) {
    // Arguments are typed
    bpf_printk("exec: %s\n", p->comm);
    return 0;
}
```

BTF tracepoints:
- Have full type information
- Support CO-RE
- Use `SEC("tp_btf/...")` 
- Use `BPF_PROG()` macro for typed arguments

## Tracepoint Best Practices

1. **Prefer tracepoints over kprobes** for stable interfaces

2. **Check tracepoint availability** — they vary by kernel version:
   ```bash
   cat /sys/kernel/debug/tracing/events/sched/sched_process_exec/format
   ```

3. **Use BTF when available** for type safety

4. **Minimize work in hot paths** — scheduler tracepoints fire frequently

5. **Batch events** with ring buffers rather than per-event perf_submit

## Exercises

1. **Process lifecycle**: Trace process fork, exec, and exit events. Build a process tree.

2. **Syscall latency**: Use enter/exit tracepoints to measure syscall duration.

3. **Block I/O tracer**: Track all block I/O operations with latency.

4. **Network tracer**: Use tcp tracepoints to log all TCP connections.

5. **Scheduler analysis**: Use sched_switch to measure time spent on CPU per process.

6. **Memory tracer**: Trace page faults using mm tracepoints.
