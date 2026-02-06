# Chapter 29: Metrics & Histograms

Aggregating data in the kernel is far more efficient than streaming raw events to userspace. This chapter covers building metrics, counters, and histograms in eBPF.

## Why Aggregate in Kernel?

Consider tracing every syscall:

| Approach | Events/sec | Overhead |
|----------|------------|----------|
| Stream all events | 100,000+ | High |
| Aggregate counts | 1 (read) | Minimal |

Kernel aggregation reduces:
- Memory usage (no per-event buffers)
- CPU usage (no userspace processing)
- I/O (less data transfer)

## Counters

### Simple Counter

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} total_count SEC(".maps");

SEC("kprobe/...")
int count_calls(struct pt_regs *ctx) {
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&total_count, &key);
    if (count)
        __sync_fetch_and_add(count, 1);
    return 0;
}
```

### Per-CPU Counter (Better Performance)

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} total_count SEC(".maps");

SEC("kprobe/...")
int count_calls(struct pt_regs *ctx) {
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&total_count, &key);
    if (count)
        (*count)++;  // No atomic needed - per-CPU
    return 0;
}
```

Read from userspace (sum all CPUs):

```python
# BCC
total = sum(b["total_count"][0])  # Index 0, sum across CPUs
print(f"Total calls: {total}")
```

### Counting by Key

```c
// Count syscalls per process
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);    // PID
    __type(value, __u64);  // Count
} syscall_count SEC(".maps");

SEC("tp/raw_syscalls/sys_enter")
int count_syscalls(void *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    __u64 *count = bpf_map_lookup_elem(&syscall_count, &pid);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&syscall_count, &pid, &one, BPF_ANY);
    }

    return 0;
}
```

### Multi-Dimensional Counting

```c
struct key {
    __u32 pid;
    __u32 syscall_nr;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct key);
    __type(value, __u64);
} syscall_matrix SEC(".maps");

SEC("tp/raw_syscalls/sys_enter")
int count_matrix(struct trace_event_raw_sys_enter *ctx) {
    struct key k = {
        .pid = bpf_get_current_pid_tgid() >> 32,
        .syscall_nr = ctx->id,
    };

    __u64 *count = bpf_map_lookup_elem(&syscall_matrix, &k);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&syscall_matrix, &k, &one, BPF_ANY);
    }

    return 0;
}
```

## Histograms

Histograms capture the distribution of values (like latency).

### Linear Histogram

Fixed-width buckets:

```c
#define MAX_SLOTS 64
#define SLOT_WIDTH 1000  // 1000ns = 1us per slot

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_SLOTS);
    __type(key, __u32);
    __type(value, __u64);
} latency_hist SEC(".maps");

static __always_inline void record_latency(__u64 ns) {
    __u32 slot = ns / SLOT_WIDTH;
    if (slot >= MAX_SLOTS)
        slot = MAX_SLOTS - 1;

    __u64 *count = bpf_map_lookup_elem(&latency_hist, &slot);
    if (count)
        __sync_fetch_and_add(count, 1);
}
```

### Log2 Histogram (Power-of-2 Buckets)

Better for wide-ranging values:

```c
#define MAX_SLOTS 32  // Covers 0 to 2^31

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_SLOTS);
    __type(key, __u32);
    __type(value, __u64);
} latency_log2 SEC(".maps");

// Log2 approximation
static __always_inline __u32 log2(__u64 v) {
    __u32 r = 0;
    while (v >>= 1)
        r++;
    return r;
}

static __always_inline void record_latency_log2(__u64 ns) {
    __u32 slot = log2(ns);
    if (slot >= MAX_SLOTS)
        slot = MAX_SLOTS - 1;

    __u64 *count = bpf_map_lookup_elem(&latency_log2, &slot);
    if (count)
        __sync_fetch_and_add(count, 1);
}
```

Bucket ranges:
- Slot 0: 0-1
- Slot 1: 2-3
- Slot 10: 1024-2047
- Slot 20: ~1M-2M

### BCC Histogram Macros

BCC provides convenient histogram macros:

```python
program = r"""
BPF_HISTOGRAM(latency);

int trace_return(struct pt_regs *ctx) {
    u64 lat_ns = /* calculate latency */;
    latency.increment(bpf_log2l(lat_ns));
    return 0;
}
"""

b = BPF(text=program)
# ...
b["latency"].print_log2_hist("latency (ns)")
```

Output:

```
latency (ns)        : count    distribution
    0 -> 1          : 0        |                                    |
    2 -> 3          : 0        |                                    |
    4 -> 7          : 12       |*                                   |
    8 -> 15         : 45       |****                                |
   16 -> 31         : 234      |************************            |
   32 -> 63         : 389      |****************************************|
   64 -> 127        : 156      |****************                    |
  128 -> 255        : 23       |**                                  |
```

## Latency Measurement Pattern

### Enter/Exit with Hash Map

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);    // Thread ID
    __type(value, __u64);  // Start time
} start_times SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 32);
    __type(key, __u32);
    __type(value, __u64);
} latency_hist SEC(".maps");

SEC("kprobe/vfs_read")
int trace_read_enter(struct pt_regs *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_times, &id, &ts, BPF_ANY);
    return 0;
}

SEC("kretprobe/vfs_read")
int trace_read_return(struct pt_regs *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u64 *start = bpf_map_lookup_elem(&start_times, &id);
    if (!start)
        return 0;

    __u64 delta = bpf_ktime_get_ns() - *start;
    bpf_map_delete_elem(&start_times, &id);

    // Record in histogram
    __u32 slot = log2(delta / 1000);  // Convert to us
    if (slot >= 32)
        slot = 31;

    __u64 *count = bpf_map_lookup_elem(&latency_hist, &slot);
    if (count)
        __sync_fetch_and_add(count, 1);

    return 0;
}
```

## Percentiles with Quantile Sketches

Exact percentiles require storing all values. For efficiency, use approximate methods:

### Simple Quantile Tracking

Track min, max, count, sum:

```c
struct stats {
    __u64 count;
    __u64 sum;
    __u64 min;
    __u64 max;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats);
} latency_stats SEC(".maps");

static __always_inline void record_stats(__u64 value) {
    __u32 key = 0;
    struct stats *s = bpf_map_lookup_elem(&latency_stats, &key);
    if (!s)
        return;

    s->count++;
    s->sum += value;

    if (s->count == 1 || value < s->min)
        s->min = value;
    if (value > s->max)
        s->max = value;
}
```

Calculate in userspace:

```python
stats = b["latency_stats"][0]
count = sum(s.count for s in stats)
total = sum(s.sum for s in stats)
min_val = min(s.min for s in stats if s.count > 0)
max_val = max(s.max for s in stats if s.count > 0)
avg = total / count if count > 0 else 0
```

### Histogram-Based Percentiles

Estimate percentiles from histogram:

```python
def percentile_from_hist(hist, p):
    """Estimate p-th percentile from histogram."""
    total = sum(hist.values())
    target = total * p / 100
    cumsum = 0

    for bucket, count in sorted(hist.items()):
        cumsum += count
        if cumsum >= target:
            # Return bucket midpoint
            return 2 ** bucket  # For log2 histogram

    return 0

# Usage
hist = {i: b["latency_hist"][i].value for i in range(32)}
p50 = percentile_from_hist(hist, 50)
p99 = percentile_from_hist(hist, 99)
```

## Rate Limiting Metrics

Don't overwhelm userspace with metrics:

```c
#define REPORT_INTERVAL_NS (1000000000ULL)  // 1 second

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} last_report SEC(".maps");

static __always_inline int should_report(void) {
    __u32 key = 0;
    __u64 now = bpf_ktime_get_ns();
    __u64 *last = bpf_map_lookup_elem(&last_report, &key);

    if (!last || now - *last >= REPORT_INTERVAL_NS) {
        bpf_map_update_elem(&last_report, &key, &now, BPF_ANY);
        return 1;
    }
    return 0;
}
```

## Complete Example: Read Latency Tracker

```python
#!/usr/bin/env python3
from bcc import BPF
from time import sleep

program = r"""
#include <linux/sched.h>

BPF_HASH(start, u64);
BPF_HISTOGRAM(read_latency);
BPF_PERCPU_ARRAY(stats, u64, 4);  // [count, sum, min, max]

int trace_read_enter(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    start.update(&id, &ts);
    return 0;
}

int trace_read_return(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u64 *tsp = start.lookup(&id);
    if (!tsp)
        return 0;

    u64 delta = bpf_ktime_get_ns() - *tsp;
    start.delete(&id);

    // Record histogram
    read_latency.increment(bpf_log2l(delta / 1000));  // us

    // Update stats
    u32 idx = 0;
    u64 *count = stats.lookup(&idx);
    if (count) (*count)++;

    idx = 1;
    u64 *sum = stats.lookup(&idx);
    if (sum) (*sum) += delta;

    return 0;
}
"""

b = BPF(text=program)
b.attach_kprobe(event="vfs_read", fn_name="trace_read_enter")
b.attach_kretprobe(event="vfs_read", fn_name="trace_read_return")

print("Tracing read() latency... Ctrl+C to stop")

try:
    while True:
        sleep(5)
        print("\n" + "="*60)

        # Stats
        stats = b["stats"]
        count = sum(stats[0])
        total_ns = sum(stats[1])
        avg_us = (total_ns / count / 1000) if count > 0 else 0

        print(f"Reads: {count}, Avg latency: {avg_us:.1f} us")

        # Histogram
        b["read_latency"].print_log2_hist("latency (us)")

        # Clear for next interval
        b["read_latency"].clear()
        stats.clear()

except KeyboardInterrupt:
    pass
```

## Prometheus Integration Pattern

Export metrics in Prometheus format:

```python
from prometheus_client import Counter, Histogram, start_http_server

# Prometheus metrics
syscall_total = Counter('syscall_total', 'Total syscalls', ['syscall'])
read_latency = Histogram('read_latency_seconds', 'Read latency',
                         buckets=[.001, .005, .01, .05, .1, .5, 1])

def export_metrics():
    # Read from BPF maps and update Prometheus metrics
    for k, v in b["syscall_count"].items():
        syscall_total.labels(syscall=str(k.value)).inc(v.value)

    # Export histogram
    hist = b["read_latency"]
    for bucket_idx in range(32):
        count = hist[bucket_idx].value
        if count:
            latency_us = 2 ** bucket_idx
            latency_s = latency_us / 1_000_000
            read_latency.observe(latency_s)

start_http_server(8000)
```

## Exercises

1. **Syscall histogram**: Build a histogram of syscall latencies by syscall number.

2. **Network metrics**: Count packets and bytes per protocol with per-CPU maps.

3. **Percentile tracker**: Implement p50, p95, p99 estimation from a histogram.

4. **Rate counter**: Track events per second with rolling windows.

5. **Multi-dimensional**: Create a histogram keyed by (process, operation) tuple.

6. **Export to Prometheus**: Build a complete exporter that scrapes BPF metrics periodically.
