# Part 4: Observability & Troubleshooting

You have learned C, understood how eBPF works, and built programs that intercept and manipulate packets. Now you will use eBPF for the thing it does better than any other technology on Linux: **observability**.

If you have ever used Python's `logging` module, `cProfile`, or tools like `strace` and `tcpdump`, you already understand the desire to see what your systems are doing. eBPF takes that idea and pushes it to its logical extreme -- you can instrument **any kernel function**, collect **any metric**, and trace **any event**, all with near-zero overhead and without modifying the software you are observing.

## Why eBPF for Observability?

Traditional observability tools have fundamental limitations:

| Approach | Limitation |
|----------|-----------|
| Application logging (`logging`, `print`) | Only sees what the application explicitly logs; blind to kernel behavior |
| System call tracing (`strace`) | Massive overhead (ptrace-based); unusable in production |
| Packet capture (`tcpdump`) | Only sees network traffic; can't correlate with processes |
| Profiling (`perf`, `cProfile`) | Sampling-based; misses short-lived events |
| Kernel modules | Dangerous; crash the kernel if you get it wrong |

eBPF eliminates these trade-offs. Your programs run inside the kernel at native speed, see everything the kernel sees, and are guaranteed safe by the verifier. You can run them in production without fear.

!!! tip "The Python Analogy"
    Think of eBPF observability like Python's `sys.settrace()` -- but for the entire Linux kernel. With `sys.settrace()`, you register a callback that fires on every function call, return, and line execution in your Python process. eBPF lets you do the same thing for **kernel functions**, **syscalls**, **scheduler decisions**, **network events**, and more. The difference is that eBPF does it with negligible overhead.

## Tracing vs Profiling vs Monitoring

These three terms get confused constantly. Here is how they differ:

### Tracing

**Tracing** captures individual events as they happen. Every TCP connection, every syscall, every function call -- you see each one with full context (timestamp, PID, arguments, return value).

```
# Tracing output: every event is recorded
14:23:01.234  PID=1892  connect() -> 10.0.0.5:443  duration=2.3ms
14:23:01.237  PID=1892  connect() -> 10.0.0.5:443  duration=1.1ms
14:23:01.301  PID=4510  connect() -> 10.0.0.8:80   duration=45.2ms
```

**When to use it:** Debugging specific issues, understanding system behavior, root cause analysis.

### Profiling

**Profiling** samples the system at regular intervals to build a statistical picture. Instead of recording every event, you periodically ask "what is the CPU doing right now?" and aggregate the answers.

```
# Profiling output: aggregated statistics
Function                   Samples    %
tcp_sendmsg                  1,204   23.1%
tcp_write_xmit                 892   17.1%
__netif_receive_skb_core       567   10.9%
```

**When to use it:** Finding performance bottlenecks, understanding CPU or memory usage patterns.

### Monitoring

**Monitoring** collects metrics continuously and exposes them for alerting and dashboards. Counters, gauges, histograms -- aggregated numbers that tell you the health of your system over time.

```
# Monitoring output: time-series metrics
tcp_connections_total{state="established"} 1,247
tcp_retransmits_total 42
tcp_connect_latency_seconds{quantile="0.99"} 0.045
```

**When to use it:** Production health, SLO tracking, alerting.

eBPF can do all three. The same technology powers tracing tools like `bpftrace`, profilers like continuous profiling agents, and monitoring exporters that feed Prometheus.

## The Observability Stack

Every eBPF observability system follows the same three-layer architecture:

```
 +------------------------------------------+
 |          Userspace (Your Code)            |
 |  Display, aggregate, export, alert       |
 |  Python script / Go binary / dashboard   |
 +------------------+-----------------------+
                    |
          Maps / Ring Buffers / Perf Buffers
           (kernel-to-userspace transport)
                    |
 +------------------+-----------------------+
 |          Kernel (eBPF Programs)           |
 |  Collect data at hook points             |
 |  Filter, aggregate, enrich in-kernel     |
 +------------------------------------------+
```

**Layer 1: Collection (kernel-side eBPF programs)**

Your eBPF programs attach to kernel hook points -- kprobes, tracepoints, perf events -- and fire whenever the event occurs. They extract the data you care about (PID, packet headers, latencies, function arguments) and either store it in a map or push it to userspace via a ring buffer.

**Layer 2: Transport (maps and buffers)**

BPF maps (`BPF_MAP_TYPE_HASH`, `BPF_MAP_TYPE_ARRAY`, `BPF_MAP_TYPE_PERCPU_ARRAY`) store aggregated data that userspace reads periodically. Ring buffers (`BPF_MAP_TYPE_RINGBUF`) and perf buffers (`BPF_MAP_TYPE_PERF_EVENT_ARRAY`) push individual events to userspace in real time.

**Layer 3: Consumption (userspace programs)**

Your Python script, Go binary, or C program reads from the maps or buffers. It might print events to the terminal, compute histograms, export metrics to Prometheus, or send data to a logging pipeline.

!!! note "In-Kernel Aggregation"
    A key advantage of eBPF is that you can aggregate data **inside the kernel** before sending it to userspace. Instead of streaming every packet to userspace and counting there (like `tcpdump | wc -l`), you increment a counter in a BPF map and read the total periodically. This is why eBPF observability has such low overhead -- you minimize the expensive kernel-to-userspace data transfer.

## What This Part Covers

| Chapter | Topic | Key Takeaway |
|---------|-------|--------------|
| [Ch 26: Tracing with Kprobes](ch26-tracing-with-kprobes.md) | Dynamic kernel function tracing | Attach to any kernel function and read its arguments |
| [Ch 27: Tracepoints](ch27-tracepoints.md) | Static kernel instrumentation | Stable, structured, lower overhead than kprobes |
| [Ch 28: Perf & Ring Buffers](ch28-perf-and-ring-buffers.md) | Kernel-to-userspace event streaming | How to get events out of the kernel efficiently |
| [Ch 29: Metrics & Histograms](ch29-metrics-and-histograms.md) | In-kernel counters and distributions | Aggregate data in the kernel for low-overhead monitoring |
| [Ch 30: Practical Debugging](ch30-practical-debugging.md) | Debugging eBPF programs | What to do when your eBPF programs do not work |

## Prerequisites

Before starting Part 4, you should be comfortable with:

- **BPF maps** -- hash maps, arrays, creating and reading them (Chapter 12)
- **BPF helpers** -- `bpf_get_current_pid_tgid()`, `bpf_probe_read_kernel()`, `bpf_ktime_get_ns()` (Chapter 13)
- **The verifier** -- understanding error messages, fixing common rejections (Chapter 14)
- **Both toolchains** -- writing programs in BCC (Python) and libbpf (C) (Chapters 15-16)
- **Networking structs** -- `struct sock`, `struct iphdr`, `struct tcphdr` (Chapter 8)

If any of these feel shaky, revisit the relevant chapter before continuing.

## The Python Developer's Advantage

As a Python developer, you have an advantage in observability work. You are already used to:

- **Scripting quick tools** -- BCC lets you write eBPF tracing scripts as fast as you write Python scripts
- **Data processing** -- You know how to parse, aggregate, and display data
- **Libraries like Prometheus client** -- You can integrate eBPF metrics into existing monitoring pipelines
- **Interactive exploration** -- BCC's Python interface lets you iterate on eBPF programs as interactively as a Jupyter notebook

The workflow for eBPF observability looks a lot like data engineering: collect raw events, transform them, aggregate, and present. You already know how to do the last three steps. This part teaches you the first.

Let's start with [Chapter 26: Tracing with Kprobes](ch26-tracing-with-kprobes.md).
