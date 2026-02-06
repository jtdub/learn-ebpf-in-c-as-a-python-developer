# Project 01: Syscall Tracer

Build a system call tracer that monitors syscalls made by any process on the system. This is your first complete eBPF project and introduces the fundamental pattern of kernel instrumentation with userspace processing.

## What You'll Build

A tool that:

- Traces all `execve` syscalls system-wide
- Captures process name, PID, and arguments
- Filters by process name or UID
- Outputs formatted events to the console

## Learning Objectives

- Attach eBPF programs to kprobes
- Read syscall arguments from registers
- Use BPF maps to communicate with userspace
- Handle strings safely in eBPF

## Prerequisites

Make sure you've read:

- Part 1: C Fundamentals (Ch 1-9)
- Part 2: eBPF Fundamentals through Ch 15 (BCC & Python)

## Architecture

```
┌─────────────────────────────────────────────────┐
│                   User Space                     │
│  ┌───────────────────────────────────────────┐  │
│  │            Python (BCC)                    │  │
│  │  - Load BPF program                        │  │
│  │  - Read events from perf buffer            │  │
│  │  - Format and display output               │  │
│  └───────────────────────────────────────────┘  │
│                       ▲                          │
│                       │ perf buffer              │
├───────────────────────┼─────────────────────────┤
│                       │     Kernel Space         │
│  ┌───────────────────┴───────────────────────┐  │
│  │            BPF Program                     │  │
│  │  - Attached to kprobe:__x64_sys_execve    │  │
│  │  - Read arguments, PID, comm               │  │
│  │  - Submit event to perf buffer             │  │
│  └───────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
```

## Step 1: Basic Execve Tracer

Create `syscall_tracer.py`:

```python
#!/usr/bin/env python3
"""Syscall tracer - traces execve calls system-wide."""
from bcc import BPF

# BPF program
bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct event {
    u32 pid;
    u32 uid;
    char comm[16];
    char filename[256];
};

BPF_PERF_OUTPUT(events);

int trace_execve(struct pt_regs *ctx,
                 const char __user *filename,
                 const char __user *const __user *argv,
                 const char __user *const __user *envp) {
    struct event event = {};

    // Get PID and UID
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // Get command name
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // Read filename from userspace
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), filename);

    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

# Initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="__x64_sys_execve", fn_name="trace_execve")

# Process events
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print(f"{event.pid:6d} {event.uid:5d} {event.comm.decode():16s} {event.filename.decode()}")

print(f"{'PID':>6} {'UID':>5} {'COMM':16s} FILENAME")

b["events"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break
```

Run it:

```bash
sudo python3 syscall_tracer.py
```

Open another terminal and run commands — you'll see them traced.

## Step 2: Capture Arguments

Enhance to capture command-line arguments:

```python
#!/usr/bin/env python3
"""Syscall tracer with argument capture."""
from bcc import BPF

bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define ARGSIZE 128
#define MAXARG  20

struct event {
    u32 pid;
    u32 uid;
    char comm[16];
    char filename[256];
    char args[ARGSIZE];
    int args_count;
};

BPF_PERF_OUTPUT(events);

int trace_execve(struct pt_regs *ctx,
                 const char __user *filename,
                 const char __user *const __user *argv,
                 const char __user *const __user *envp) {
    struct event event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), filename);

    // Read arguments
    #pragma unroll
    for (int i = 0; i < MAXARG && i < ARGSIZE / 16; i++) {
        const char *argp = NULL;
        bpf_probe_read_user(&argp, sizeof(argp), &argv[i]);
        if (!argp)
            break;

        int off = i * 16;
        if (off >= ARGSIZE - 16)
            break;

        bpf_probe_read_user_str(&event.args[off], 16, argp);
        event.args_count++;
    }

    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_kprobe(event="__x64_sys_execve", fn_name="trace_execve")

def print_event(cpu, data, size):
    event = b["events"].event(data)
    args = event.args.decode('utf-8', errors='replace').split('\x00')
    args = ' '.join([a for a in args if a][:event.args_count])
    print(f"{event.pid:6d} {event.comm.decode():16s} {event.filename.decode()} {args}")

print(f"{'PID':>6} {'COMM':16s} COMMAND")

b["events"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break
```

## Step 3: Add Filtering

Add filtering by process name:

```python
#!/usr/bin/env python3
"""Syscall tracer with filtering."""
from bcc import BPF
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-c", "--comm", help="Filter by command name")
parser.add_argument("-u", "--uid", type=int, help="Filter by UID")
args = parser.parse_args()

# Build filter code
filter_code = ""
if args.comm:
    filter_code += f"""
    char target_comm[] = "{args.comm}";
    char current_comm[16];
    bpf_get_current_comm(&current_comm, sizeof(current_comm));
    
    // Simple string comparison
    int match = 1;
    #pragma unroll
    for (int i = 0; i < {len(args.comm)}; i++) {{
        if (current_comm[i] != target_comm[i]) {{
            match = 0;
            break;
        }}
    }}
    if (!match) return 0;
"""

if args.uid is not None:
    filter_code += f"""
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if (uid != {args.uid}) return 0;
"""

bpf_text = f"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct event {{
    u32 pid;
    u32 uid;
    char comm[16];
    char filename[256];
}};

BPF_PERF_OUTPUT(events);

int trace_execve(struct pt_regs *ctx,
                 const char __user *filename,
                 const char __user *const __user *argv,
                 const char __user *const __user *envp) {{
    {filter_code}

    struct event event = {{}};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), filename);

    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}}
"""

b = BPF(text=bpf_text)
b.attach_kprobe(event="__x64_sys_execve", fn_name="trace_execve")

def print_event(cpu, data, size):
    event = b["events"].event(data)
    print(f"{event.pid:6d} {event.uid:5d} {event.comm.decode():16s} {event.filename.decode()}")

print(f"{'PID':>6} {'UID':>5} {'COMM':16s} FILENAME")

b["events"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break
```

Usage:

```bash
# Filter by command
sudo python3 syscall_tracer.py -c bash

# Filter by UID
sudo python3 syscall_tracer.py -u 1000
```

## Step 4: Add Return Value Tracing

Trace both entry and exit to capture return values:

```python
#!/usr/bin/env python3
"""Syscall tracer with return values."""
from bcc import BPF

bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct event {
    u32 pid;
    u64 ts;
    int retval;
    char comm[16];
    char filename[256];
    u8 is_return;
};

BPF_HASH(inflight, u64, struct event);
BPF_PERF_OUTPUT(events);

int trace_execve_entry(struct pt_regs *ctx,
                       const char __user *filename,
                       const char __user *const __user *argv,
                       const char __user *const __user *envp) {
    u64 id = bpf_get_current_pid_tgid();
    struct event event = {};

    event.ts = bpf_ktime_get_ns();
    event.pid = id >> 32;
    event.is_return = 0;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), filename);

    inflight.update(&id, &event);
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

int trace_execve_return(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct event *ep = inflight.lookup(&id);
    if (!ep)
        return 0;

    struct event event = *ep;
    event.retval = PT_REGS_RC(ctx);
    event.is_return = 1;

    events.perf_submit(ctx, &event, sizeof(event));
    inflight.delete(&id);
    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_kprobe(event="__x64_sys_execve", fn_name="trace_execve_entry")
b.attach_kretprobe(event="__x64_sys_execve", fn_name="trace_execve_return")

def print_event(cpu, data, size):
    event = b["events"].event(data)
    if event.is_return:
        status = "OK" if event.retval == 0 else f"ERR:{event.retval}"
        print(f"  └─ {status}")
    else:
        print(f"{event.pid:6d} {event.comm.decode():16s} {event.filename.decode()}")

print(f"{'PID':>6} {'COMM':16s} FILENAME")

b["events"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break
```

## Step 5: Add Statistics

Track syscall statistics with a map:

```python
#!/usr/bin/env python3
"""Syscall tracer with statistics."""
from bcc import BPF
from time import sleep
import signal
import sys

bpf_text = r"""
#include <uapi/linux/ptrace.h>

BPF_HASH(syscall_count, u32, u64);
BPF_HASH(pid_count, u32, u64);

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u32 syscall = args->id;
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u64 *val;
    
    // Count syscalls
    val = syscall_count.lookup_or_try_init(&syscall, &(u64){0});
    if (val) (*val)++;

    // Count by PID
    val = pid_count.lookup_or_try_init(&pid, &(u64){0});
    if (val) (*val)++;

    return 0;
}
"""

b = BPF(text=bpf_text)

# Syscall names (partial list)
syscall_names = {
    0: "read", 1: "write", 2: "open", 3: "close",
    59: "execve", 60: "exit", 62: "kill",
}

def print_stats():
    print("\n=== Syscall Counts ===")
    for k, v in sorted(b["syscall_count"].items(), key=lambda x: x[1].value, reverse=True)[:10]:
        name = syscall_names.get(k.value, f"syscall_{k.value}")
        print(f"  {name:20s} {v.value:10d}")
    
    print("\n=== Top PIDs ===")
    for k, v in sorted(b["pid_count"].items(), key=lambda x: x[1].value, reverse=True)[:5]:
        print(f"  PID {k.value:6d}: {v.value:10d} syscalls")

def signal_handler(sig, frame):
    print_stats()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

print("Tracing syscalls... Ctrl+C to show stats")
while True:
    sleep(1)
```

## Final Complete Solution

```python
#!/usr/bin/env python3
"""
Syscall Tracer - Complete Solution
Traces execve syscalls with filtering, arguments, and return values.
"""
from bcc import BPF
import argparse
import ctypes

parser = argparse.ArgumentParser(description="Trace execve syscalls")
parser.add_argument("-c", "--comm", help="Filter by command name")
parser.add_argument("-u", "--uid", type=int, help="Filter by UID")
parser.add_argument("-p", "--pid", type=int, help="Filter by PID")
parser.add_argument("-t", "--timestamp", action="store_true", help="Show timestamps")
args = parser.parse_args()

# Build filter
filter_code = ""
if args.pid:
    filter_code += f"if ((bpf_get_current_pid_tgid() >> 32) != {args.pid}) return 0;\n"
if args.uid is not None:
    filter_code += f"if ((bpf_get_current_uid_gid() & 0xFFFFFFFF) != {args.uid}) return 0;\n"

bpf_text = f"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define ARGSIZE  256
#define MAXARGS  8

struct event {{
    u64 ts;
    u32 pid;
    u32 ppid;
    u32 uid;
    int retval;
    char comm[16];
    char filename[256];
    char args[ARGSIZE];
    u8 is_return;
}};

BPF_HASH(inflight, u64, struct event);
BPF_PERF_OUTPUT(events);

static __always_inline int trace_entry(struct pt_regs *ctx,
                                        const char __user *filename,
                                        const char __user *const __user *argv) {{
    {filter_code}

    u64 id = bpf_get_current_pid_tgid();
    struct event event = {{}};

    // Get task info
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    event.ts = bpf_ktime_get_ns();
    event.pid = id >> 32;
    event.ppid = BPF_CORE_READ(task, real_parent, tgid);
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.is_return = 0;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), filename);

    // Read arguments
    int off = 0;
    #pragma unroll
    for (int i = 1; i < MAXARGS; i++) {{
        const char *argp = NULL;
        bpf_probe_read_user(&argp, sizeof(argp), &argv[i]);
        if (!argp) break;
        
        if (off > 0 && off < ARGSIZE - 1) {{
            event.args[off++] = ' ';
        }}
        
        int len = bpf_probe_read_user_str(&event.args[off], 
                                           ARGSIZE - off, argp);
        if (len > 0) off += len - 1;
        if (off >= ARGSIZE - 16) break;
    }}

    inflight.update(&id, &event);
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}}

static __always_inline int trace_return(struct pt_regs *ctx) {{
    u64 id = bpf_get_current_pid_tgid();
    struct event *ep = inflight.lookup(&id);
    if (!ep) return 0;

    struct event event = *ep;
    event.retval = PT_REGS_RC(ctx);
    event.is_return = 1;
    event.ts = bpf_ktime_get_ns();

    events.perf_submit(ctx, &event, sizeof(event));
    inflight.delete(&id);
    return 0;
}}

int syscall__execve(struct pt_regs *ctx,
                    const char __user *filename,
                    const char __user *const __user *argv,
                    const char __user *const __user *envp) {{
    return trace_entry(ctx, filename, argv);
}}

int do_ret_execve(struct pt_regs *ctx) {{
    return trace_return(ctx);
}}
"""

b = BPF(text=bpf_text)
execve_fnname = b.get_syscall_fnname("execve")
b.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")
b.attach_kretprobe(event=execve_fnname, fn_name="do_ret_execve")

start_ts = 0

def print_event(cpu, data, size):
    global start_ts
    event = b["events"].event(data)
    
    if start_ts == 0:
        start_ts = event.ts
    
    ts = (event.ts - start_ts) / 1e9
    
    if event.is_return:
        retval = event.retval
        if retval >= 0:
            status = f"\\033[32mOK\\033[0m"
        else:
            status = f"\\033[31mERR:{retval}\\033[0m"
        print(f"  └── {{status}}")
    else:
        timestamp = f"{{ts:8.3f}} " if args.timestamp else ""
        filename = event.filename.decode('utf-8', errors='replace')
        argv = event.args.decode('utf-8', errors='replace')
        comm = event.comm.decode()
        
        print(f"{{timestamp}}{{event.pid:6d}} {{event.ppid:6d}} {{event.uid:5d}} "
              f"{{comm:16s}} {{filename}} {{argv}}")

# Header
timestamp_hdr = "TIME(s) " if args.timestamp else ""
print(f"{{timestamp_hdr}}{{' PID':>6}} {{'PPID':>6}} {{'UID':>5}} {{'COMM':16s}} COMMAND")

b["events"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break
```

## Testing

```bash
# Basic tracing
sudo python3 syscall_tracer.py

# Filter to your user
sudo python3 syscall_tracer.py -u $(id -u)

# With timestamps
sudo python3 syscall_tracer.py -t

# Watch a specific command spawn children
sudo python3 syscall_tracer.py -c bash
```

## Challenges

1. **Add syscall filtering**: Trace other syscalls like `open`, `connect`, or `clone`.

2. **JSON output**: Output events as JSON for log aggregation.

3. **Parent chain**: Show the full parent process chain (grandparent, etc.).

4. **Latency tracking**: Measure time between entry and return.

5. **Container awareness**: Add container/cgroup information to events.

## What's Next

In [Project 02: Packet Counter](../project02-packet-counter/index.md), you'll move from tracing syscalls to processing network packets with XDP.
