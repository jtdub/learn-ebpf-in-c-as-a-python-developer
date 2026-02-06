# Chapter 12: BPF Maps

Maps are how eBPF programs store data and communicate with userspace. They're the shared memory between the kernel-side eBPF program and your userspace application. Without maps, eBPF programs would be stateless — unable to count events, store configuration, or report data.

Think of maps as kernel-resident data structures with a key-value interface. Python developers: imagine a `dict` that lives in the kernel and can be accessed simultaneously by your eBPF program and your Python script.

## Why Maps?

eBPF programs have severe constraints:

- **No heap allocation** — you can't `malloc()` anything
- **Limited stack** — only 512 bytes
- **No global state** — between invocations, local variables are gone

Maps solve these problems. They provide:

- **Persistent storage** — data survives between eBPF program invocations
- **Shared access** — kernel and userspace can read/write the same data
- **Pre-allocated memory** — the kernel allocates map memory when you create it

## Map Types Overview

| Map Type | Description | Key | Value | Use Case |
|----------|-------------|-----|-------|----------|
| `BPF_MAP_TYPE_HASH` | Hash table | Any fixed-size | Any fixed-size | General lookups, connection tracking |
| `BPF_MAP_TYPE_ARRAY` | Array | `__u32` (index) | Any fixed-size | Configuration, fixed-size tables |
| `BPF_MAP_TYPE_PERCPU_HASH` | Per-CPU hash | Any fixed-size | Any fixed-size | Counters without lock contention |
| `BPF_MAP_TYPE_PERCPU_ARRAY` | Per-CPU array | `__u32` | Any fixed-size | Per-CPU statistics |
| `BPF_MAP_TYPE_PERF_EVENT_ARRAY` | Perf buffer | `__u32` (CPU) | `__u32` (fd) | Streaming events to userspace |
| `BPF_MAP_TYPE_RINGBUF` | Ring buffer | N/A | Variable | Streaming events (modern) |
| `BPF_MAP_TYPE_LRU_HASH` | LRU hash | Any fixed-size | Any fixed-size | Bounded caches |
| `BPF_MAP_TYPE_PROG_ARRAY` | Program array | `__u32` | Program fd | Tail calls |
| `BPF_MAP_TYPE_STACK_TRACE` | Stack traces | `__u32` | Stack frames | Profiling |
| `BPF_MAP_TYPE_SOCKMAP` | Socket map | `__u32` | Socket | Socket redirection |
| `BPF_MAP_TYPE_SOCKHASH` | Socket hash | Any fixed-size | Socket | Socket lookup |

## Defining Maps

### Modern BTF-Style (libbpf)

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} my_map SEC(".maps");
```

The macros `__uint()` and `__type()` are defined in `<bpf/bpf_helpers.h>`:

```c
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
```

### BCC-Style

```python
# In BCC (Python), maps are created with macros:
BPF_HASH(my_map, u32, u64);          # Hash map
BPF_ARRAY(my_array, u64, 1024);      # Array
BPF_PERF_OUTPUT(events);             # Perf event array
BPF_RINGBUF_OUTPUT(ringbuf, 8);      # Ring buffer (pages)
```

## Hash Maps

The most versatile map type. Works like a Python `dict` with fixed-size keys and values.

### Definition

```c
struct connection_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

struct connection_value {
    __u64 packets;
    __u64 bytes;
    __u64 start_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct connection_key);
    __type(value, struct connection_value);
} connections SEC(".maps");
```

### Operations

```c
// Lookup — returns pointer to value, or NULL if not found
struct connection_value *val = bpf_map_lookup_elem(&connections, &key);
if (!val) {
    // Key not found
}

// Update — insert or replace
struct connection_value new_val = {.packets = 1, .bytes = 64};
bpf_map_update_elem(&connections, &key, &new_val, BPF_ANY);

// Delete
bpf_map_delete_elem(&connections, &key);
```

### Update Flags

| Flag | Meaning |
|------|---------|
| `BPF_ANY` | Create or update |
| `BPF_NOEXIST` | Create only (fail if exists) |
| `BPF_EXIST` | Update only (fail if doesn't exist) |

!!! warning "Always Check bpf_map_lookup_elem Return"
    The verifier **requires** you to check for NULL before dereferencing:
    ```c
    // WRONG — verifier rejects
    struct value *v = bpf_map_lookup_elem(&map, &key);
    v->count++;  // REJECTED: v might be NULL

    // RIGHT
    struct value *v = bpf_map_lookup_elem(&map, &key);
    if (v) {
        v->count++;
    }
    ```

## Array Maps

Arrays are fixed-size and always fully allocated. The key is always a `__u32` index.

### Definition

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");
```

### Use Cases

- Configuration (small, fixed-size)
- Protocol-specific counters (e.g., one per protocol number)
- When you need guaranteed O(1) lookup

### Operations

```c
__u32 idx = 0;
__u64 *count = bpf_map_lookup_elem(&counters, &idx);
if (count) {
    (*count)++;  // Increment in-place
}
```

!!! note "Array Elements Always Exist"
    Unlike hash maps, array lookups return valid pointers for any index < max_entries. The value is initialized to zero. But you still must check for NULL (verifier requirement) and bounds.

## Per-CPU Maps

Regular maps have a single value per key, accessed by all CPUs. This causes **lock contention** when multiple CPUs update the same entry frequently.

Per-CPU maps store a **separate value for each CPU**:

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} packet_count SEC(".maps");

SEC("xdp")
int count_packets(struct xdp_md *ctx) {
    __u32 idx = 0;
    __u64 *count = bpf_map_lookup_elem(&packet_count, &idx);
    if (count) {
        (*count)++;  // Each CPU updates its own counter — no lock!
    }
    return XDP_PASS;
}
```

In userspace, you read all per-CPU values and sum them:

```python
# BCC Python
counts = packet_count.values()  # Returns list, one value per CPU
total = sum(counts)
```

```c
// libbpf C
__u64 values[num_cpus];
bpf_map_lookup_elem(map_fd, &key, values);
__u64 total = 0;
for (int i = 0; i < num_cpus; i++) {
    total += values[i];
}
```

### When to Use Per-CPU

| Use Case | Map Type |
|----------|----------|
| High-frequency counters | Per-CPU array |
| Connection tracking (updates less frequent) | Regular hash |
| Configuration (read-only from eBPF) | Regular array |
| Per-connection state | Regular hash |

## Ring Buffer

The ring buffer (`BPF_MAP_TYPE_RINGBUF`, kernel 5.8+) is the modern way to stream events from eBPF to userspace. It replaces the older perf event array.

### Definition

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // Size in bytes (must be power of 2)
} events SEC(".maps");
```

### Sending Events

```c
struct event {
    __u32 pid;
    __u8 comm[16];
};

SEC("kprobe/tcp_connect")
int trace_connect(struct pt_regs *ctx) {
    struct event *e;

    // Reserve space in the ring buffer
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;  // Buffer full
    }

    // Fill in the event
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Submit the event
    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

### Ring Buffer vs Perf Buffer

| Feature | Ring Buffer | Perf Buffer |
|---------|-------------|-------------|
| Per-CPU | Shared (one buffer) | Separate per CPU |
| Event ordering | Global ordering | Per-CPU ordering |
| Memory efficiency | Better | Wastes memory per CPU |
| Variable-length events | Yes | Yes |
| Availability | Kernel 5.8+ | Kernel 4.4+ |

Ring buffer is preferred for new code.

## LRU Hash

LRU (Least Recently Used) hash maps automatically evict old entries when full. This is crucial for connection tracking where you can't predict entry count.

```c
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, struct conn_key);
    __type(value, struct conn_value);
} connections SEC(".maps");
```

When you insert into a full LRU hash, the least recently accessed entry is evicted. Regular hash maps return an error when full.

## Accessing Maps from Userspace

### BCC (Python)

```python
from bcc import BPF

b = BPF(text="""...""")

# Access map by name
my_map = b["my_map"]

# Lookup
val = my_map[key]

# Update
my_map[key] = value

# Iterate
for k, v in my_map.items():
    print(f"{k.value} -> {v.value}")

# Clear
my_map.clear()
```

### libbpf (C)

```c
// Get map file descriptor
int map_fd = bpf_map__fd(skel->maps.my_map);

// Lookup
struct value val;
int err = bpf_map_lookup_elem(map_fd, &key, &val);

// Update
err = bpf_map_update_elem(map_fd, &key, &val, BPF_ANY);

// Delete
err = bpf_map_delete_elem(map_fd, &key);

// Iterate
struct key cur_key, next_key;
while (bpf_map_get_next_key(map_fd, &cur_key, &next_key) == 0) {
    bpf_map_lookup_elem(map_fd, &next_key, &val);
    // Process...
    cur_key = next_key;
}
```

### bpftool

```bash
# List maps
sudo bpftool map list

# Dump map contents
sudo bpftool map dump id 42

# Lookup specific key
sudo bpftool map lookup id 42 key 0x01 0x00 0x00 0x00

# Update
sudo bpftool map update id 42 key 0x01 0x00 0x00 0x00 value 0x05 0x00 0x00 0x00

# Delete
sudo bpftool map delete id 42 key 0x01 0x00 0x00 0x00
```

## Map Pinning

By default, maps are destroyed when the program that created them exits. **Pinning** saves a map to the BPF filesystem, allowing other programs to access it:

```c
// Pin when loading
bpf_map__pin(skel->maps.my_map, "/sys/fs/bpf/my_map");

// Load from pin
int map_fd = bpf_obj_get("/sys/fs/bpf/my_map");
```

```bash
# Pin with bpftool
sudo bpftool map pin id 42 /sys/fs/bpf/my_map

# Unpin
sudo rm /sys/fs/bpf/my_map
```

## Common Patterns

### Atomic Counter

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} counter SEC(".maps");

SEC("xdp")
int count(struct xdp_md *ctx) {
    __u32 idx = 0;
    __u64 *c = bpf_map_lookup_elem(&counter, &idx);
    if (c) (*c)++;
    return XDP_PASS;
}
```

### Configuration Table

```c
struct config {
    __u32 target_port;
    __u8 enabled;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} config SEC(".maps");

SEC("xdp")
int filter(struct xdp_md *ctx) {
    __u32 idx = 0;
    struct config *cfg = bpf_map_lookup_elem(&config, &idx);
    if (!cfg || !cfg->enabled)
        return XDP_PASS;
    // Use cfg->target_port...
}
```

### Event Streaming

```c
struct event {
    __u64 timestamp;
    __u32 pid;
    __u32 tgid;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("kprobe/sys_execve")
int trace_exec(struct pt_regs *ctx) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

## Exercises

1. **Counter implementation**: Create a per-CPU array map that counts packets by protocol (TCP, UDP, ICMP, other). Read and sum the counters from userspace.

2. **Connection table**: Design a hash map to track active connections (5-tuple → stats). Include packet count, byte count, and start time.

3. **Ring buffer events**: Send structured events from a kprobe to userspace via ring buffer. Parse and print them in Python.

4. **LRU behavior**: Create an LRU hash with max_entries=10. Insert 15 entries and observe which are evicted.

5. **Map pinning**: Pin a map, exit your program, then use bpftool to read the map contents. Start a new program that reads the pinned map.

6. **Python comparison**: Implement the same data structure in Python (dict for hash, list for array) and compare the API differences.
