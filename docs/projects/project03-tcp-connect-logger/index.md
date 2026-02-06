# Project 03: TCP Connect Logger

Build a TCP connection logger that captures every outbound connection attempt with full details. This project bridges packet processing and syscall tracing, introducing ring buffers for efficient event streaming.

## What You'll Build

A tool that:

- Traces `tcp_v4_connect` kernel function
- Captures source/destination IPs and ports
- Uses ring buffers for event delivery
- Provides JSON output for log aggregation

## Learning Objectives

- Use kprobes for kernel function tracing
- Work with ring buffers (vs perf buffers)
- Handle network byte order conversions
- Structure events for log processing

## Prerequisites

- Part 1: C Fundamentals
- Part 2: eBPF Fundamentals through Ch 15
- Ch 26: Tracing with Kprobes
- Ch 28: Perf & Ring Buffers

## Architecture

```
Application calls connect()
         │
         ▼
┌──────────────────────┐
│   Kernel tcp_v4_connect │
│         │            │
│    ┌────┴────┐       │
│    │ kprobe  │       │
│    └────┬────┘       │
│         │            │
│    ┌────┴────┐       │
│    │  Ring   │       │
│    │ Buffer  │       │
│    └────┬────┘       │
└─────────┼────────────┘
          │
          ▼
┌──────────────────────┐
│   Python Consumer    │
│   - Poll events      │
│   - Format JSON      │
│   - Write to stdout  │
└──────────────────────┘
```

## Step 1: Basic Connection Tracer

Create `tcp_connect_logger.py`:

```python
#!/usr/bin/env python3
"""TCP Connect Logger - traces outbound TCP connections."""
from bcc import BPF
import socket
import struct

bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct event {
    u32 pid;
    u32 uid;
    u32 saddr;
    u32 daddr;
    u16 dport;
    char comm[16];
};

BPF_PERF_OUTPUT(events);

int trace_connect(struct pt_regs *ctx, struct sock *sk) {
    struct event event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // Read socket fields
    event.saddr = sk->__sk_common.skc_rcv_saddr;
    event.daddr = sk->__sk_common.skc_daddr;
    event.dport = sk->__sk_common.skc_dport;

    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect")

def ip_to_str(addr):
    return socket.inet_ntoa(struct.pack("I", addr))

def print_event(cpu, data, size):
    event = b["events"].event(data)
    print(f"{event.pid:6d} {event.comm.decode():16s} "
          f"{ip_to_str(event.saddr)}:{event.dport} -> "
          f"{ip_to_str(event.daddr)}:{socket.ntohs(event.dport)}")

print(f"{'PID':>6} {'COMM':16s} CONNECTION")

b["events"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break
```

Run:

```bash
sudo python3 tcp_connect_logger.py
```

Test in another terminal:

```bash
curl https://example.com
```

## Step 2: Add Connection Result Tracking

Track both entry and return to capture success/failure:

```python
#!/usr/bin/env python3
"""TCP Connect Logger with results."""
from bcc import BPF
import socket
import struct

bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct event {
    u64 ts;
    u32 pid;
    u32 uid;
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
    int retval;
    char comm[16];
    u8 is_return;
};

struct conn_info {
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
    u64 ts;
};

BPF_HASH(inflight, u64, struct conn_info);
BPF_PERF_OUTPUT(events);

int trace_connect_entry(struct pt_regs *ctx, struct sock *sk) {
    u64 id = bpf_get_current_pid_tgid();

    struct conn_info info = {};
    info.saddr = sk->__sk_common.skc_rcv_saddr;
    info.daddr = sk->__sk_common.skc_daddr;
    info.lport = sk->__sk_common.skc_num;
    info.dport = sk->__sk_common.skc_dport;
    info.ts = bpf_ktime_get_ns();

    inflight.update(&id, &info);
    return 0;
}

int trace_connect_return(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct conn_info *infop = inflight.lookup(&id);
    if (!infop)
        return 0;

    struct event event = {};
    event.ts = bpf_ktime_get_ns();
    event.pid = id >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.saddr = infop->saddr;
    event.daddr = infop->daddr;
    event.lport = infop->lport;
    event.dport = infop->dport;
    event.retval = PT_REGS_RC(ctx);
    event.is_return = 1;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    events.perf_submit(ctx, &event, sizeof(event));
    inflight.delete(&id);
    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_return")

def ip_to_str(addr):
    return socket.inet_ntoa(struct.pack("I", addr))

start_ts = 0

def print_event(cpu, data, size):
    global start_ts
    event = b["events"].event(data)
    
    if start_ts == 0:
        start_ts = event.ts
    
    ts = (event.ts - start_ts) / 1e9
    status = "OK" if event.retval == 0 else f"ERR:{event.retval}"
    
    print(f"{ts:9.3f} {event.pid:6d} {event.comm.decode():16s} "
          f"{ip_to_str(event.saddr)}:{event.lport} -> "
          f"{ip_to_str(event.daddr)}:{socket.ntohs(event.dport)} "
          f"[{status}]")

print(f"{'TIME(s)':>9} {'PID':>6} {'COMM':16s} CONNECTION")

b["events"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break
```

## Step 3: Use Ring Buffer

Upgrade from perf buffer to ring buffer for better performance:

```python
#!/usr/bin/env python3
"""TCP Connect Logger with ring buffer."""
from bcc import BPF
import socket
import struct
import ctypes

bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct event {
    u64 ts;
    u32 pid;
    u32 uid;
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
    int retval;
    char comm[16];
};

struct conn_info {
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
    u64 ts;
};

BPF_HASH(inflight, u64, struct conn_info);
BPF_RINGBUF_OUTPUT(events, 1 << 20);  // 1MB ring buffer

int trace_connect_entry(struct pt_regs *ctx, struct sock *sk) {
    u64 id = bpf_get_current_pid_tgid();

    struct conn_info info = {};
    info.saddr = sk->__sk_common.skc_rcv_saddr;
    info.daddr = sk->__sk_common.skc_daddr;
    info.lport = sk->__sk_common.skc_num;
    info.dport = sk->__sk_common.skc_dport;
    info.ts = bpf_ktime_get_ns();

    inflight.update(&id, &info);
    return 0;
}

int trace_connect_return(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct conn_info *infop = inflight.lookup(&id);
    if (!infop)
        return 0;

    struct event *event = events.ringbuf_reserve(sizeof(struct event));
    if (!event)
        return 0;

    event->ts = bpf_ktime_get_ns();
    event->pid = id >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->saddr = infop->saddr;
    event->daddr = infop->daddr;
    event->lport = infop->lport;
    event->dport = infop->dport;
    event->retval = PT_REGS_RC(ctx);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    events.ringbuf_submit(event, 0);
    inflight.delete(&id);
    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_return")

# Define ctypes structure matching the BPF event
class Event(ctypes.Structure):
    _fields_ = [
        ("ts", ctypes.c_ulonglong),
        ("pid", ctypes.c_uint),
        ("uid", ctypes.c_uint),
        ("saddr", ctypes.c_uint),
        ("daddr", ctypes.c_uint),
        ("lport", ctypes.c_ushort),
        ("dport", ctypes.c_ushort),
        ("retval", ctypes.c_int),
        ("comm", ctypes.c_char * 16),
    ]

def ip_to_str(addr):
    return socket.inet_ntoa(struct.pack("I", addr))

start_ts = [0]

def handle_event(ctx, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Event)).contents
    
    if start_ts[0] == 0:
        start_ts[0] = event.ts
    
    ts = (event.ts - start_ts[0]) / 1e9
    status = "OK" if event.retval == 0 else f"ERR:{event.retval}"
    
    print(f"{ts:9.3f} {event.pid:6d} {event.comm.decode():16s} "
          f"{ip_to_str(event.saddr)}:{event.lport} -> "
          f"{ip_to_str(event.daddr)}:{socket.ntohs(event.dport)} "
          f"[{status}]")

print(f"{'TIME(s)':>9} {'PID':>6} {'COMM':16s} CONNECTION")

b["events"].open_ring_buffer(handle_event)
while True:
    try:
        b.ring_buffer_poll()
    except KeyboardInterrupt:
        break
```

## Step 4: JSON Output

Add JSON output for log aggregation:

```python
#!/usr/bin/env python3
"""TCP Connect Logger with JSON output."""
from bcc import BPF
import socket
import struct
import ctypes
import json
import sys
import argparse
from datetime import datetime

parser = argparse.ArgumentParser()
parser.add_argument("-j", "--json", action="store_true", help="JSON output")
parser.add_argument("-p", "--pid", type=int, help="Filter by PID")
parser.add_argument("-u", "--uid", type=int, help="Filter by UID")
args = parser.parse_args()

# Build filter
filter_code = ""
if args.pid:
    filter_code += f"if ((bpf_get_current_pid_tgid() >> 32) != {args.pid}) return 0;\n"
if args.uid:
    filter_code += f"if ((bpf_get_current_uid_gid() & 0xFFFFFFFF) != {args.uid}) return 0;\n"

bpf_text = f"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct event {{
    u64 ts;
    u32 pid;
    u32 uid;
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
    int retval;
    u64 latency_ns;
    char comm[16];
}};

struct conn_info {{
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
    u64 ts;
}};

BPF_HASH(inflight, u64, struct conn_info);
BPF_RINGBUF_OUTPUT(events, 1 << 20);

int trace_connect_entry(struct pt_regs *ctx, struct sock *sk) {{
    {filter_code}
    
    u64 id = bpf_get_current_pid_tgid();

    struct conn_info info = {{}};
    info.saddr = sk->__sk_common.skc_rcv_saddr;
    info.daddr = sk->__sk_common.skc_daddr;
    info.lport = sk->__sk_common.skc_num;
    info.dport = sk->__sk_common.skc_dport;
    info.ts = bpf_ktime_get_ns();

    inflight.update(&id, &info);
    return 0;
}}

int trace_connect_return(struct pt_regs *ctx) {{
    u64 id = bpf_get_current_pid_tgid();
    struct conn_info *infop = inflight.lookup(&id);
    if (!infop)
        return 0;

    u64 now = bpf_ktime_get_ns();

    struct event *event = events.ringbuf_reserve(sizeof(struct event));
    if (!event) {{
        inflight.delete(&id);
        return 0;
    }}

    event->ts = now;
    event->pid = id >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->saddr = infop->saddr;
    event->daddr = infop->daddr;
    event->lport = infop->lport;
    event->dport = infop->dport;
    event->retval = PT_REGS_RC(ctx);
    event->latency_ns = now - infop->ts;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    events.ringbuf_submit(event, 0);
    inflight.delete(&id);
    return 0;
}}
"""

b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_return")

class Event(ctypes.Structure):
    _fields_ = [
        ("ts", ctypes.c_ulonglong),
        ("pid", ctypes.c_uint),
        ("uid", ctypes.c_uint),
        ("saddr", ctypes.c_uint),
        ("daddr", ctypes.c_uint),
        ("lport", ctypes.c_ushort),
        ("dport", ctypes.c_ushort),
        ("retval", ctypes.c_int),
        ("latency_ns", ctypes.c_ulonglong),
        ("comm", ctypes.c_char * 16),
    ]

def ip_to_str(addr):
    return socket.inet_ntoa(struct.pack("I", addr))

start_ts = [0]

def handle_event(ctx, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Event)).contents
    
    if start_ts[0] == 0:
        start_ts[0] = event.ts
    
    if args.json:
        output = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": "tcp_connect",
            "pid": event.pid,
            "uid": event.uid,
            "comm": event.comm.decode(),
            "src_ip": ip_to_str(event.saddr),
            "src_port": event.lport,
            "dst_ip": ip_to_str(event.daddr),
            "dst_port": socket.ntohs(event.dport),
            "result": "success" if event.retval == 0 else "failed",
            "return_code": event.retval,
            "latency_us": event.latency_ns / 1000,
        }
        print(json.dumps(output), flush=True)
    else:
        ts = (event.ts - start_ts[0]) / 1e9
        status = "OK" if event.retval == 0 else f"ERR:{event.retval}"
        latency = event.latency_ns / 1000
        
        print(f"{ts:9.3f} {event.pid:6d} {event.comm.decode():16s} "
              f"{ip_to_str(event.saddr)}:{event.lport} -> "
              f"{ip_to_str(event.daddr)}:{socket.ntohs(event.dport)} "
              f"[{status}] {latency:.0f}us")

if not args.json:
    print(f"{'TIME(s)':>9} {'PID':>6} {'COMM':16s} CONNECTION", file=sys.stderr)

b["events"].open_ring_buffer(handle_event)
while True:
    try:
        b.ring_buffer_poll()
    except KeyboardInterrupt:
        break
```

## Step 5: Complete Solution

```python
#!/usr/bin/env python3
"""
TCP Connect Logger - Complete Solution
Traces TCP connections with latency, DNS resolution, and flexible output.
"""
from bcc import BPF
import socket
import struct
import ctypes
import json
import sys
import argparse
from datetime import datetime
from collections import defaultdict

parser = argparse.ArgumentParser(description="TCP Connect Logger")
parser.add_argument("-j", "--json", action="store_true", help="JSON output")
parser.add_argument("-p", "--pid", type=int, help="Filter by PID")
parser.add_argument("-u", "--uid", type=int, help="Filter by UID")
parser.add_argument("-c", "--comm", help="Filter by command name")
parser.add_argument("--port", type=int, help="Filter by destination port")
parser.add_argument("-s", "--stats", action="store_true", help="Show statistics on exit")
parser.add_argument("-d", "--dns", action="store_true", help="Resolve hostnames")
args = parser.parse_args()

# Build filter
filters = []
if args.pid:
    filters.append(f"if ((bpf_get_current_pid_tgid() >> 32) != {args.pid}) return 0;")
if args.uid:
    filters.append(f"if ((bpf_get_current_uid_gid() & 0xFFFFFFFF) != {args.uid}) return 0;")
if args.port:
    filters.append(f"if (ntohs(sk->__sk_common.skc_dport) != {args.port}) return 0;")

filter_code = "\n".join(filters)

bpf_text = f"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct event {{
    u64 ts;
    u32 pid;
    u32 uid;
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
    int retval;
    u64 latency_ns;
    char comm[16];
}};

struct conn_info {{
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
    u64 ts;
}};

BPF_HASH(inflight, u64, struct conn_info);
BPF_RINGBUF_OUTPUT(events, 1 << 20);

// Statistics
BPF_HASH(connect_count, u32, u64);
BPF_HASH(error_count, u32, u64);
BPF_HISTOGRAM(latency_hist);

int trace_connect_entry(struct pt_regs *ctx, struct sock *sk) {{
    {filter_code}
    
    u64 id = bpf_get_current_pid_tgid();

    struct conn_info info = {{}};
    info.saddr = sk->__sk_common.skc_rcv_saddr;
    info.daddr = sk->__sk_common.skc_daddr;
    info.lport = sk->__sk_common.skc_num;
    info.dport = sk->__sk_common.skc_dport;
    info.ts = bpf_ktime_get_ns();

    inflight.update(&id, &info);
    return 0;
}}

int trace_connect_return(struct pt_regs *ctx) {{
    u64 id = bpf_get_current_pid_tgid();
    struct conn_info *infop = inflight.lookup(&id);
    if (!infop)
        return 0;

    u64 now = bpf_ktime_get_ns();
    u64 latency = now - infop->ts;

    // Update statistics
    u32 pid = id >> 32;
    u64 *count = connect_count.lookup_or_try_init(&pid, &(u64){{0}});
    if (count) (*count)++;
    
    int ret = PT_REGS_RC(ctx);
    if (ret != 0) {{
        u64 *errs = error_count.lookup_or_try_init(&pid, &(u64){{0}});
        if (errs) (*errs)++;
    }}
    
    // Latency histogram (microseconds)
    latency_hist.increment(bpf_log2l(latency / 1000));

    struct event *event = events.ringbuf_reserve(sizeof(struct event));
    if (!event) {{
        inflight.delete(&id);
        return 0;
    }}

    event->ts = now;
    event->pid = pid;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->saddr = infop->saddr;
    event->daddr = infop->daddr;
    event->lport = infop->lport;
    event->dport = infop->dport;
    event->retval = ret;
    event->latency_ns = latency;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    events.ringbuf_submit(event, 0);
    inflight.delete(&id);
    return 0;
}}
"""

b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_return")

class Event(ctypes.Structure):
    _fields_ = [
        ("ts", ctypes.c_ulonglong),
        ("pid", ctypes.c_uint),
        ("uid", ctypes.c_uint),
        ("saddr", ctypes.c_uint),
        ("daddr", ctypes.c_uint),
        ("lport", ctypes.c_ushort),
        ("dport", ctypes.c_ushort),
        ("retval", ctypes.c_int),
        ("latency_ns", ctypes.c_ulonglong),
        ("comm", ctypes.c_char * 16),
    ]

def ip_to_str(addr):
    return socket.inet_ntoa(struct.pack("I", addr))

# DNS cache
dns_cache = {}

def resolve_hostname(ip):
    if not args.dns:
        return ip
    if ip in dns_cache:
        return dns_cache[ip]
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        dns_cache[ip] = hostname
        return hostname
    except:
        dns_cache[ip] = ip
        return ip

start_ts = [0]
stats = defaultdict(lambda: {"connects": 0, "errors": 0, "total_latency": 0})

def handle_event(ctx, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Event)).contents
    
    if start_ts[0] == 0:
        start_ts[0] = event.ts
    
    # Command filter (done in userspace for string matching)
    comm = event.comm.decode()
    if args.comm and args.comm not in comm:
        return
    
    # Track stats
    stats[comm]["connects"] += 1
    if event.retval != 0:
        stats[comm]["errors"] += 1
    stats[comm]["total_latency"] += event.latency_ns
    
    dst_ip = ip_to_str(event.daddr)
    dst_port = socket.ntohs(event.dport)
    
    if args.json:
        output = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": "tcp_connect",
            "pid": event.pid,
            "uid": event.uid,
            "comm": comm,
            "src_ip": ip_to_str(event.saddr),
            "src_port": event.lport,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "dst_host": resolve_hostname(dst_ip) if args.dns else dst_ip,
            "result": "success" if event.retval == 0 else "failed",
            "return_code": event.retval,
            "latency_us": event.latency_ns / 1000,
        }
        print(json.dumps(output), flush=True)
    else:
        ts = (event.ts - start_ts[0]) / 1e9
        status = "\\033[32mOK\\033[0m" if event.retval == 0 else f"\\033[31mERR:{event.retval}\\033[0m"
        latency = event.latency_ns / 1000
        
        dst = resolve_hostname(dst_ip) if args.dns else dst_ip
        
        print(f"{ts:9.3f} {event.pid:6d} {comm:16s} "
              f"{ip_to_str(event.saddr)}:{event.lport} -> "
              f"{dst}:{dst_port} "
              f"[{status}] {latency:>6.0f}us")

def print_stats():
    print("\n" + "=" * 60, file=sys.stderr)
    print("Connection Statistics by Command", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    print(f"{'Command':<20} {'Connects':>10} {'Errors':>10} {'Avg Latency':>12}", file=sys.stderr)
    print("-" * 60, file=sys.stderr)
    
    for comm, s in sorted(stats.items(), key=lambda x: x[1]["connects"], reverse=True):
        avg_lat = s["total_latency"] / s["connects"] / 1000 if s["connects"] > 0 else 0
        print(f"{comm:<20} {s['connects']:>10} {s['errors']:>10} {avg_lat:>10.0f}us", file=sys.stderr)
    
    print("\nLatency Histogram (microseconds):", file=sys.stderr)
    b["latency_hist"].print_log2_hist("latency (us)", file=sys.stderr)

if not args.json:
    print(f"{'TIME(s)':>9} {'PID':>6} {'COMM':16s} CONNECTION", file=sys.stderr)

b["events"].open_ring_buffer(handle_event)
try:
    while True:
        b.ring_buffer_poll()
except KeyboardInterrupt:
    if args.stats:
        print_stats()
```

## Testing

```bash
# Basic usage
sudo python3 tcp_connect_logger.py

# JSON output
sudo python3 tcp_connect_logger.py -j | jq .

# Filter to curl
sudo python3 tcp_connect_logger.py -c curl

# With DNS resolution and stats
sudo python3 tcp_connect_logger.py -d -s

# Filter to HTTPS connections
sudo python3 tcp_connect_logger.py --port 443
```

## Challenges

1. **IPv6 support**: Trace `tcp_v6_connect` for IPv6 connections.

2. **Container awareness**: Add container ID or cgroup info to events.

3. **Connection pooling detection**: Identify connection reuse patterns.

4. **Rate limiting alerts**: Alert when connection rate exceeds threshold.

5. **Failed connection analysis**: Group and analyze failed connections by error code.

## What's Next

In [Project 04: Header Inspector](../project04-header-inspector/index.md), you'll transition to libbpf and build a TC-based packet inspector.
