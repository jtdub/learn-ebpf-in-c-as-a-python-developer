# Chapter 28: Perf & Ring Buffers

Getting data from kernel to userspace is fundamental to eBPF observability. This chapter covers perf buffers and ring buffers — the two main mechanisms for streaming events.

## Perf Buffer vs Ring Buffer

| Feature | Perf Buffer | Ring Buffer |
|---------|-------------|-------------|
| Kernel version | 4.4+ | 5.8+ |
| Per-CPU | Yes (multiple buffers) | No (single buffer) |
| Memory efficiency | Lower | Higher |
| Event ordering | Per-CPU only | Global |
| API complexity | More complex | Simpler |
| Performance | Good | Better |

**Recommendation**: Use ring buffers if your kernel supports them (5.8+).

## Perf Buffers

### BCC Pattern

```python
#!/usr/bin/env python3
from bcc import BPF
import ctypes as ct

program = r"""
#include <linux/sched.h>

struct event {
    u32 pid;
    char comm[16];
};

BPF_PERF_OUTPUT(events);

int trace_exec(void *ctx) {
    struct event e = {};
    e.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));

    events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}
"""

class Event(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("comm", ct.c_char * 16),
    ]

def handle_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Event)).contents
    print(f"CPU{cpu}: pid={event.pid} comm={event.comm.decode()}")

b = BPF(text=program)
b.attach_kprobe(event="__x64_sys_execve", fn_name="trace_exec")

b["events"].open_perf_buffer(handle_event)

while True:
    b.perf_buffer_poll()
```

### libbpf Pattern

```c
// events.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct event {
    __u32 pid;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

SEC("kprobe/__x64_sys_execve")
int trace_exec(struct pt_regs *ctx) {
    struct event e = {};

    e.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                          &e, sizeof(e));
    return 0;
}
```

```c
// events.c (userspace)
#include <stdio.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "events.skel.h"

struct event {
    __u32 pid;
    char comm[16];
};

static void handle_event(void *ctx, int cpu, void *data, __u32 size) {
    struct event *e = data;
    printf("CPU%d: pid=%d comm=%s\n", cpu, e->pid, e->comm);
}

static void handle_lost(void *ctx, int cpu, __u64 cnt) {
    printf("Lost %llu events on CPU %d\n", cnt, cpu);
}

int main() {
    struct events_bpf *skel = events_bpf__open_and_load();
    events_bpf__attach(skel);

    struct perf_buffer *pb = perf_buffer__new(
        bpf_map__fd(skel->maps.events),
        8,  // pages per CPU
        handle_event,
        handle_lost,
        NULL,
        NULL
    );

    while (1) {
        perf_buffer__poll(pb, 100);  // 100ms timeout
    }
}
```

### Handling Lost Events

Events can be dropped if userspace doesn't read fast enough:

```python
def handle_lost(lost_cnt):
    print(f"Lost {lost_cnt} events!")

b["events"].open_perf_buffer(handle_event, lost_cb=handle_lost)
```

## Ring Buffers

### BCC Pattern

```python
#!/usr/bin/env python3
from bcc import BPF

program = r"""
#include <linux/sched.h>

struct event {
    u32 pid;
    char comm[16];
};

BPF_RINGBUF_OUTPUT(events, 8);  // 8 pages = 32KB

int trace_exec(void *ctx) {
    struct event *e = events.ringbuf_reserve(sizeof(*e));
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    events.ringbuf_submit(e, 0);
    return 0;
}
"""

def handle_event(ctx, data, size):
    event = b["events"].event(data)
    print(f"pid={event.pid} comm={event.comm.decode()}")

b = BPF(text=program)
b.attach_kprobe(event="__x64_sys_execve", fn_name="trace_exec")

b["events"].open_ring_buffer(handle_event)

while True:
    b.ring_buffer_poll()
```

### libbpf Pattern

```c
// ringbuf.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct event {
    __u32 pid;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // 256KB
} events SEC(".maps");

SEC("kprobe/__x64_sys_execve")
int trace_exec(struct pt_regs *ctx) {
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

```c
// ringbuf.c (userspace)
#include <stdio.h>
#include <bpf/libbpf.h>
#include "ringbuf.skel.h"

struct event {
    __u32 pid;
    char comm[16];
};

static int handle_event(void *ctx, void *data, size_t len) {
    struct event *e = data;
    printf("pid=%d comm=%s\n", e->pid, e->comm);
    return 0;
}

int main() {
    struct ringbuf_bpf *skel = ringbuf_bpf__open_and_load();
    ringbuf_bpf__attach(skel);

    struct ring_buffer *rb = ring_buffer__new(
        bpf_map__fd(skel->maps.events),
        handle_event,
        NULL,
        NULL
    );

    while (1) {
        ring_buffer__poll(rb, 100);
    }
}
```

## Ring Buffer Operations

### Reserve and Submit

```c
// Reserve space
struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
if (!e)
    return 0;  // No space

// Fill the data
e->pid = ...;

// Submit (make visible to userspace)
bpf_ringbuf_submit(e, 0);
```

### Discard

If you decide not to send an event:

```c
struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
if (!e)
    return 0;

// Check something
if (!should_send) {
    bpf_ringbuf_discard(e, 0);
    return 0;
}

e->data = ...;
bpf_ringbuf_submit(e, 0);
```

### Output (Alternative)

For simpler cases, `bpf_ringbuf_output` combines reserve+submit:

```c
struct event e = {};
e.pid = bpf_get_current_pid_tgid() >> 32;

bpf_ringbuf_output(&events, &e, sizeof(e), 0);
```

But this copies data, while reserve/submit is zero-copy.

### Flags

```c
// BPF_RB_NO_WAKEUP: Don't wake up userspace (batch events)
bpf_ringbuf_submit(e, BPF_RB_NO_WAKEUP);

// BPF_RB_FORCE_WAKEUP: Always wake up userspace
bpf_ringbuf_submit(e, BPF_RB_FORCE_WAKEUP);
```

## Polling Strategies

### Blocking Poll

```c
// Wait up to 100ms for events
ring_buffer__poll(rb, 100);
```

### Non-Blocking Consume

```c
// Process available events without waiting
ring_buffer__consume(rb);
```

### With epoll (Multiple Sources)

```c
int rb_fd = ring_buffer__epoll_fd(rb);
// Add to your epoll set
```

## Variable-Length Data

### Approach 1: Fixed Max Size

```c
struct event {
    __u32 pid;
    __u32 filename_len;
    char filename[256];  // Max size
};
```

### Approach 2: Dynamic Sizing

```c
SEC("tp/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    char filename[256];
    int len;

    // Read filename
    len = bpf_probe_read_user_str(filename, sizeof(filename),
                                   (void *)ctx->args[1]);
    if (len < 0)
        return 0;

    // Reserve exact size needed
    int event_size = sizeof(struct event_header) + len;
    struct event *e = bpf_ringbuf_reserve(&events, event_size, 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->len = len;
    bpf_probe_read_user_str(e->filename, len, (void *)ctx->args[1]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

## Performance Tuning

### Ring Buffer Sizing

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // Must be power of 2
} events SEC(".maps");
```

Size considerations:
- Too small: Events dropped under load
- Too large: Wastes memory
- Rule of thumb: Start with 256KB, increase if losing events

### Batch Processing

In userspace, process in batches for efficiency:

```c
// Instead of waking on every event
while (1) {
    ring_buffer__poll(rb, 1000);  // Longer timeout, batch events
    // Process accumulated events
}
```

### BPF-Side Batching

Don't wake up immediately:

```c
static int event_count = 0;

SEC("...")
int my_prog(void *ctx) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    // Fill event...

    event_count++;
    __u64 flags = (event_count % 100 == 0) ? 0 : BPF_RB_NO_WAKEUP;
    bpf_ringbuf_submit(e, flags);

    return 0;
}
```

## Handling Backpressure

### Detection

```c
// In BPF
struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
if (!e) {
    // Ring buffer full!
    // Increment a counter, drop event, etc.
    return 0;
}
```

### Userspace Callback for Lost Events

```python
# BCC perf buffer
def lost_cb(lost_count):
    print(f"Lost {lost_count} events - increase buffer or process faster")

b["events"].open_perf_buffer(handle_event, lost_cb=lost_cb, page_cnt=64)
```

## Complete Example: Syscall Tracer

```python
#!/usr/bin/env python3
"""Trace syscalls with timing using ring buffer."""
from bcc import BPF
from time import strftime

program = r"""
#include <linux/sched.h>

struct event {
    u64 ts;
    u64 duration_ns;
    u32 pid;
    u32 tid;
    int syscall_nr;
    long ret;
    char comm[16];
};

BPF_HASH(start, u64, u64);
BPF_RINGBUF_OUTPUT(events, 8);

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u64 id = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    start.update(&id, &ts);
    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_exit) {
    u64 id = bpf_get_current_pid_tgid();
    u64 *tsp = start.lookup(&id);
    if (!tsp)
        return 0;

    struct event *e = events.ringbuf_reserve(sizeof(*e));
    if (!e) {
        start.delete(&id);
        return 0;
    }

    e->ts = bpf_ktime_get_ns();
    e->duration_ns = e->ts - *tsp;
    e->pid = id >> 32;
    e->tid = id;
    e->syscall_nr = args->id;
    e->ret = args->ret;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    events.ringbuf_submit(e, 0);
    start.delete(&id);
    return 0;
}
"""

# Syscall names (partial)
syscalls = {
    0: "read", 1: "write", 2: "open", 3: "close",
    257: "openat", 262: "newfstatat",
}

b = BPF(text=program)

def handle_event(ctx, data, size):
    event = b["events"].event(data)
    syscall = syscalls.get(event.syscall_nr, str(event.syscall_nr))
    duration_us = event.duration_ns / 1000
    print(f"{event.comm.decode():16} {event.pid:6} {syscall:15} "
          f"{duration_us:10.1f}us ret={event.ret}")

b["events"].open_ring_buffer(handle_event)

print(f"{'COMM':16} {'PID':>6} {'SYSCALL':15} {'DURATION':>12} RETURN")
while True:
    b.ring_buffer_poll()
```

## Exercises

1. **Buffer sizing**: Experiment with different ring buffer sizes under load. Observe when events are lost.

2. **Perf vs Ring**: Implement the same tracer with both perf buffer and ring buffer. Compare memory usage and event ordering.

3. **Backpressure handling**: Create a high-frequency event source and implement graceful degradation when the buffer fills.

4. **Variable events**: Implement a tracer that captures variable-length filenames efficiently.

5. **Multi-ring**: Use multiple ring buffers for different event types with different priorities.

6. **Batching**: Implement kernel-side batching with periodic wakeups.
