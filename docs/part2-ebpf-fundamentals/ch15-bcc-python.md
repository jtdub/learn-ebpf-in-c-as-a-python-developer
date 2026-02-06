# Chapter 15: BCC & Python

BCC (BPF Compiler Collection) is a toolkit that makes eBPF accessible from Python. For Python developers, it's the most natural entry point: you write the kernel-side code in C (embedded as a Python string), and everything else — compilation, loading, attaching, reading results — happens through familiar Python APIs.

This chapter shows you how to use BCC effectively, leveraging your Python expertise while learning eBPF.

## BCC Architecture

BCC has two parts:

1. **Kernel side**: C code that runs as an eBPF program
2. **Userspace side**: Python (or Lua) code that loads, attaches, and interacts with the eBPF program

```
┌─────────────────────────────────────────────┐
│               Python Script                  │
│  ┌─────────────────────────────────────┐    │
│  │     C code as Python string         │    │
│  │  (your eBPF program)                │    │
│  └──────────────────┬──────────────────┘    │
│                     │                       │
│  BCC library compiles with clang            │
│                     │                       │
│  BCC loads program into kernel              │
└─────────────────────┼───────────────────────┘
                      │
       ═══════════════╧═══════════════════
                   KERNEL
       ═══════════════╤═══════════════════
                      │
          BPF program runs on events
                      │
          Results in BPF maps
                      │
       ═══════════════╧═══════════════════
                      │
┌─────────────────────┴───────────────────────┐
│  Python reads maps, processes data          │
└─────────────────────────────────────────────┘
```

## Installation

### Ubuntu/Debian

```bash
sudo apt-get install bpfcc-tools python3-bpfcc linux-headers-$(uname -r)
```

### Fedora

```bash
sudo dnf install bcc-tools python3-bcc kernel-devel
```

### Verify Installation

```python
python3 -c "from bcc import BPF; print('BCC OK')"
```

## Your First BCC Program

```python
#!/usr/bin/env python3
from bcc import BPF

# The C code — runs in kernel
program = r"""
int hello(void *ctx) {
    bpf_trace_printk("Hello from eBPF!\n");
    return 0;
}
"""

# Load and compile
b = BPF(text=program)

# Attach to a kernel event
b.attach_kprobe(event="sys_clone", fn_name="hello")

# Read output
print("Tracing sys_clone... Ctrl+C to exit")
b.trace_print()
```

Run it:

```bash
sudo python3 hello.py
```

Then in another terminal, run any command (which calls `sys_clone`):

```bash
ls
```

## The BPF Class

The `BPF` class is the main interface:

```python
from bcc import BPF

# From string
b = BPF(text=program_text)

# From file
b = BPF(src_file="program.c")

# With preprocessor defines
b = BPF(text=program, cflags=["-DMAX_ENTRIES=1024"])
```

### Key Methods

| Method | Purpose |
|--------|---------|
| `attach_kprobe(event, fn_name)` | Attach to kernel function entry |
| `attach_kretprobe(event, fn_name)` | Attach to kernel function return |
| `attach_tracepoint(tp, fn_name)` | Attach to tracepoint |
| `attach_xdp(dev, fn)` | Attach XDP to interface |
| `trace_print()` | Print trace_pipe output |
| `trace_fields()` | Iterate trace_pipe as fields |
| `["map_name"]` | Access a BPF map |

## Working with Maps

### Defining Maps (C Side)

BCC provides macros for common map types:

```c
// Hash map
BPF_HASH(my_hash, u32, u64);           // key: u32, value: u64
BPF_HASH(my_hash, struct key_t, struct val_t);  // Custom types

// Array
BPF_ARRAY(my_array, u64, 1024);        // 1024 entries of u64

// Per-CPU array (for counters)
BPF_PERCPU_ARRAY(counters, u64, 256);

// Perf event array (streaming events)
BPF_PERF_OUTPUT(events);

// Ring buffer (kernel 5.8+)
BPF_RINGBUF_OUTPUT(ringbuf, 8);        // 8 pages
```

### Using Maps (C Side)

```c
BPF_HASH(connections, u32, u64);

int trace_connect(void *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Lookup
    u64 *count = connections.lookup(&pid);
    if (count) {
        (*count)++;
    } else {
        // Insert
        u64 one = 1;
        connections.update(&pid, &one);
    }

    return 0;
}
```

### Reading Maps (Python Side)

```python
# Access the map
my_hash = b["my_hash"]

# Read all entries
for k, v in my_hash.items():
    print(f"Key: {k.value}, Value: {v.value}")

# Lookup specific key
key = my_hash.Key(123)
try:
    val = my_hash[key]
    print(f"Value: {val.value}")
except KeyError:
    print("Key not found")

# Update
my_hash[key] = my_hash.Leaf(456)

# Delete
del my_hash[key]

# Clear all
my_hash.clear()
```

### Per-CPU Maps

```python
# Per-CPU values are returned as a list (one per CPU)
counters = b["counters"]

for k, values in counters.items():
    total = sum(values)  # Sum across all CPUs
    print(f"Key {k.value}: {total}")
```

## Streaming Events

### Using Perf Buffer

```c
// C side
struct event_t {
    u32 pid;
    char comm[16];
};

BPF_PERF_OUTPUT(events);

int trace_exec(void *ctx) {
    struct event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
```

```python
# Python side
from bcc import BPF
import ctypes

# Define the event structure in Python (must match C)
class Event(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),
    ]

def handle_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Event)).contents
    print(f"PID {event.pid}: {event.comm.decode()}")

# Open perf buffer
b["events"].open_perf_buffer(handle_event)

# Poll for events
while True:
    b.perf_buffer_poll()
```

### Using Ring Buffer (Kernel 5.8+)

```c
// C side
struct event_t {
    u32 pid;
    char comm[16];
};

BPF_RINGBUF_OUTPUT(events, 8);

int trace_exec(void *ctx) {
    struct event_t *event = events.ringbuf_reserve(sizeof(*event));
    if (!event) return 0;

    event->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    events.ringbuf_submit(event, 0);
    return 0;
}
```

```python
# Python side
def handle_event(ctx, data, size):
    event = b["events"].event(data)
    print(f"PID {event.pid}: {event.comm.decode()}")

b["events"].open_ring_buffer(handle_event)

while True:
    b.ring_buffer_poll()
```

## Tracing Examples

### Trace System Calls

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

### Count Events by Process

```python
#!/usr/bin/env python3
from bcc import BPF
from time import sleep

program = r"""
BPF_HASH(counts, u32, u64);

int count_syscall(void *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *count = counts.lookup_or_try_init(&pid, &(u64){0});
    if (count) {
        (*count)++;
    }
    return 0;
}
"""

b = BPF(text=program)
b.attach_kprobe(event="__x64_sys_read", fn_name="count_syscall")

print("Counting reads by PID... Ctrl+C to show results")

try:
    while True:
        sleep(1)
except KeyboardInterrupt:
    pass

print("\nPID\t\tREADS")
for k, v in sorted(b["counts"].items(), key=lambda x: x[1].value, reverse=True):
    print(f"{k.value}\t\t{v.value}")
```

### Network Connection Tracer

```python
#!/usr/bin/env python3
from bcc import BPF
from socket import inet_ntop, AF_INET
import ctypes

program = r"""
#include <net/sock.h>
#include <bcc/proto.h>

struct event_t {
    u32 pid;
    u32 daddr;
    u16 dport;
    char comm[16];
};

BPF_PERF_OUTPUT(events);

int trace_connect(struct pt_regs *ctx, struct sock *sk) {
    struct event_t event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.daddr = sk->__sk_common.skc_daddr;
    event.dport = sk->__sk_common.skc_dport;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

class Event(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("daddr", ctypes.c_uint32),
        ("dport", ctypes.c_uint16),
        ("comm", ctypes.c_char * 16),
    ]

def handle_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Event)).contents
    ip = inet_ntop(AF_INET, event.daddr.to_bytes(4, 'little'))
    port = (event.dport >> 8) | ((event.dport & 0xFF) << 8)  # ntohs
    print(f"{event.comm.decode():16} {event.pid:6} -> {ip}:{port}")

b = BPF(text=program)
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect")

b["events"].open_perf_buffer(handle_event)

print(f"{'COMM':16} {'PID':6}    DESTINATION")
while True:
    b.perf_buffer_poll()
```

## XDP with BCC

```python
#!/usr/bin/env python3
from bcc import BPF
import sys

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <interface>")
    sys.exit(1)

device = sys.argv[1]

program = r"""
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

BPF_PERCPU_ARRAY(counter, u64, 1);

int xdp_count(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    u32 idx = 0;
    u64 *count = counter.lookup(&idx);
    if (count) {
        (*count)++;
    }

    return XDP_PASS;
}
"""

b = BPF(text=program)
fn = b.load_func("xdp_count", BPF.XDP)
b.attach_xdp(device, fn, 0)

print(f"Attached to {device}. Ctrl+C to exit and show count.")

try:
    from time import sleep
    while True:
        sleep(1)
except KeyboardInterrupt:
    pass

# Sum per-CPU counts
total = sum(b["counter"][0])
print(f"\nTotal packets: {total}")

# Detach
b.remove_xdp(device)
```

## BCC Helper Macros

BCC provides macros that make C code cleaner:

| Macro | Purpose |
|-------|---------|
| `PT_REGS_PARM1(ctx)` | Get first function argument |
| `PT_REGS_RC(ctx)` | Get return value (in kretprobe) |
| `BPF_HASH(name, ...)` | Declare hash map |
| `BPF_ARRAY(name, ...)` | Declare array map |
| `TRACEPOINT_PROBE(category, name)` | Attach to tracepoint |

## Debugging BCC Programs

### Print Debug Output

```c
// In C code
bpf_trace_printk("debug: x = %d\n", x);
```

```python
# In Python
b.trace_print()
# Or iterate:
for (task, pid, cpu, flags, ts, msg) in b.trace_fields():
    print(msg)
```

### Check for Errors

```python
try:
    b = BPF(text=program)
except Exception as e:
    print(f"Compilation error: {e}")
```

### Verbose Output

```python
b = BPF(text=program, debug=0x4)  # Print verifier log
```

## BCC vs libbpf

| Aspect | BCC | libbpf |
|--------|-----|--------|
| Language | Python (+ C string) | Pure C |
| Compilation | Runtime (needs clang on target) | Ahead-of-time |
| Dependencies | Heavier (LLVM, kernel headers) | Lighter |
| Portability | Recompiles on each host | CO-RE: compile once, run everywhere |
| Use case | Prototyping, one-off tools | Production, embedded |
| Learning curve | Easier for Python devs | Steeper |

**Recommendation**: Start with BCC for learning and prototyping. Move to libbpf for production deployments.

## Exercises

1. **Basic tracer**: Write a BCC program that traces `open()` syscalls and prints the filename and PID.

2. **Event counter**: Count how many times each system call is invoked over 10 seconds. Display the top 10.

3. **Latency measurement**: Measure the latency of `read()` syscalls using kprobe/kretprobe. Store the duration in a histogram.

4. **Network monitor**: Track bytes sent per process using `tcp_sendmsg`. Display totals when exiting.

5. **XDP filter**: Write an XDP program that drops ICMP packets. Attach to a test interface and verify with ping.

6. **Custom event structure**: Define a C struct with 5 fields, send events through a ring buffer, and decode them correctly in Python with ctypes.
