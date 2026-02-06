# Chapter 30: Practical Debugging

Debugging eBPF programs requires different techniques than userspace code. This chapter covers practical strategies for finding and fixing issues in your eBPF programs.

## Debugging Workflow

1. **Verify compilation** — Does it compile without errors?
2. **Check verifier** — Does the verifier accept it?
3. **Confirm attachment** — Is it attached to the right event?
4. **Test basic functionality** — Is the handler being called?
5. **Validate logic** — Is the code doing what you expect?
6. **Debug data flow** — Are maps populated correctly?

## Printf-Style Debugging

### Using bpf_trace_printk

The simplest debugging tool:

```c
SEC("kprobe/vfs_read")
int trace_read(struct pt_regs *ctx) {
    bpf_printk("vfs_read called\n");
    return 0;
}
```

Read output:

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### With Variables

```c
SEC("xdp")
int debug_xdp(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    bpf_printk("proto=%x len=%d\n",
               bpf_ntohs(eth->h_proto),
               ctx->data_end - ctx->data);

    return XDP_PASS;
}
```

### Limitations

- Max 3 format arguments
- Limited format specifiers
- Performance overhead
- Global output (all programs)

### BCC's trace_print

```python
b = BPF(text=program)
b.attach_kprobe(...)
b.trace_print()  # Formatted output
# Or iterate:
for (_, pid, cpu, flags, ts, msg) in b.trace_fields():
    print(f"[{cpu}] {msg}")
```

## Verifier Debugging

### Understanding Verifier Errors

Common error types:

| Error | Meaning |
|-------|---------|
| `invalid mem access` | Accessing memory without bounds check |
| `unbounded variable offset` | Variable used as offset without bounds |
| `R0 is not a scalar` | Function didn't return expected type |
| `back-edge from insn X to Y` | Unbounded loop detected |
| `unreachable insn` | Dead code after return |

### Getting Verbose Output

```python
# BCC
b = BPF(text=program, debug=0x4)  # Enable verifier debug
```

```bash
# bpftool
sudo bpftool prog load my_prog.bpf.o /sys/fs/bpf/my_prog -d
```

### Reading Verifier Log

```
...
17: (79) r6 = *(u64 *)(r1 +104)
18: (bf) r1 = r6
19: (85) call bpf_get_current_pid_tgid#14
20: (77) r0 >>= 32
21: (63) *(u32 *)(r10 -8) = r0
22: (79) r1 = *(u64 *)(r10 -32)     ; R1_w=scalar()
23: (0f) r1 += r6
24: (71) r2 = *(u8 *)(r1 +0)
R1 unbounded memory access, make sure to bounds check any such access
```

Line 24 is the error — accessing `r1` without bounds check.

### Fixing Common Errors

#### Invalid mem access

```c
// WRONG
struct ethhdr *eth = data;
__u16 proto = eth->h_proto;  // No bounds check!

// RIGHT
struct ethhdr *eth = data;
if ((void *)(eth + 1) > data_end)
    return XDP_PASS;
__u16 proto = eth->h_proto;  // OK
```

#### Unbounded loop

```c
// WRONG
for (int i = 0; i < n; i++) {  // n is unbounded
    // ...
}

// RIGHT
#define MAX_ITER 100
for (int i = 0; i < MAX_ITER && i < n; i++) {
    // ...
}
```

## Checking if Programs are Loaded

```bash
# List all loaded programs
sudo bpftool prog list

# Find yours by name
sudo bpftool prog list | grep my_prog

# Show details
sudo bpftool prog show id 123
```

## Checking if Programs are Attached

```bash
# Network attachments (XDP, TC)
sudo bpftool net show

# Cgroup attachments
sudo bpftool cgroup show /sys/fs/cgroup/unified

# Kprobes/tracepoints (via tracefs)
sudo cat /sys/kernel/debug/tracing/kprobe_events
sudo cat /sys/kernel/debug/tracing/enabled_events
```

## Map Inspection

### Dump Map Contents

```bash
# List maps
sudo bpftool map list

# Dump all entries
sudo bpftool map dump id 42

# Lookup specific key
sudo bpftool map lookup id 42 key 0x01 0x00 0x00 0x00
```

### From Python (BCC)

```python
# Read hash map
for k, v in b["my_hash"].items():
    print(f"{k.value}: {v.value}")

# Read array
for i in range(10):
    print(f"[{i}] = {b["my_array"][i].value}")

# Per-CPU array (returns list of values, one per CPU)
for k, vals in b["percpu_array"].items():
    total = sum(vals)
    print(f"[{k.value}] = {total} (across CPUs)")
```

## Tracing eBPF Events

### XDP/TC Program Tracing

```bash
# Enable XDP tracepoints
sudo perf trace -e 'xdp:*'

# Or specific events
sudo perf trace -e 'xdp:xdp_exception'
```

### Program Statistics

```bash
# Enable BPF stats
sudo sysctl kernel.bpf_stats_enabled=1

# View run count and time
sudo bpftool prog show id 123
# Shows: run_cnt and run_time_ns
```

## Testing Strategies

### Unit Testing with BPF_PROG_TEST_RUN

Test XDP/TC programs without real traffic:

```c
// Userspace test code
#include <bpf/bpf.h>

char packet[] = {
    // Ethernet header
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  // dst MAC
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // src MAC
    0x08, 0x00,                          // EtherType (IPv4)
    // IP header...
};

struct bpf_test_run_opts opts = {
    .sz = sizeof(opts),
    .data_in = packet,
    .data_size_in = sizeof(packet),
    .data_out = output,
    .data_size_out = sizeof(output),
};

int err = bpf_prog_test_run_opts(prog_fd, &opts);
printf("Return: %d, duration: %u ns\n", opts.retval, opts.duration);
```

### Integration Testing

Create test namespaces:

```bash
# Create network namespace
sudo ip netns add test

# Create veth pair
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth1 netns test

# Attach XDP to veth0
sudo ip link set veth0 xdp obj my_prog.bpf.o sec xdp

# Send test traffic through veth1 (in namespace)
sudo ip netns exec test ping 10.0.0.1
```

## Performance Analysis

### CPU Overhead

```bash
# Profile BPF program CPU usage
sudo perf record -e cycles -g -- sleep 10
sudo perf report
```

### Instruction Count

```bash
# Show program complexity
sudo bpftool prog dump xlated id 123 | wc -l
```

### Timing Measurement

Add timing to your program:

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} timing SEC(".maps");

SEC("xdp")
int timed_prog(struct xdp_md *ctx) {
    __u64 start = bpf_ktime_get_ns();

    // Your logic here

    __u64 elapsed = bpf_ktime_get_ns() - start;
    __u32 key = 0;
    bpf_map_update_elem(&timing, &key, &elapsed, BPF_ANY);

    return XDP_PASS;
}
```

## Common Pitfalls

### 1. Forgetting to Return

```c
// WRONG
SEC("kprobe/...")
int my_probe(struct pt_regs *ctx) {
    if (condition)
        bpf_printk("found\n");
    // No return - verifier error!
}

// RIGHT
SEC("kprobe/...")
int my_probe(struct pt_regs *ctx) {
    if (condition)
        bpf_printk("found\n");
    return 0;
}
```

### 2. Stack Overflow

```c
// WRONG - 1MB buffer on stack!
char buffer[1024*1024];

// RIGHT - Use map or smaller buffer
char buffer[256];

// Or per-CPU array for larger buffers
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[4096]);
} scratch SEC(".maps");
```

### 3. Dereferencing User Pointers

```c
// WRONG
char *user_str = (char *)PT_REGS_PARM1(ctx);
char c = *user_str;  // Crash!

// RIGHT
char buf[64];
bpf_probe_read_user_str(buf, sizeof(buf), user_str);
```

### 4. Map Not Found

```python
# WRONG - map name must match exactly
counts = b["count"]  # Error if map is named "counts"

# Check available maps
print(b.keys())  # ['counts', 'events', ...]
```

### 5. Byte Order

```c
// WRONG
if (ip->saddr == 0x0100007F)  // "127.0.0.1" in wrong order

// RIGHT
if (ip->saddr == bpf_htonl(0x7F000001))  // Or use inet_addr()
```

## Debugging Checklist

1. ✅ Program compiles without errors
2. ✅ Verifier accepts program (check with `-d`)
3. ✅ Program appears in `bpftool prog list`
4. ✅ Attachment shows in `bpftool net/cgroup show`
5. ✅ Basic `bpf_printk` shows handler is called
6. ✅ Maps are populated (check with `bpftool map dump`)
7. ✅ Return values are correct
8. ✅ No kernel warnings in `dmesg`

## Tools Summary

| Tool | Purpose |
|------|---------|
| `bpftool prog` | List/inspect programs |
| `bpftool map` | Inspect map contents |
| `bpftool net` | Show network attachments |
| `trace_pipe` | Read bpf_printk output |
| `perf trace` | Trace eBPF events |
| `BPF_PROG_TEST_RUN` | Unit test programs |

## Exercises

1. **Debug a broken program**: Intentionally break an XDP program (remove bounds checks) and practice reading verifier errors.

2. **Map inspector**: Write a Python script that periodically dumps all maps from a running BPF program.

3. **Performance baseline**: Measure the overhead of your XDP program using BPF_PROG_TEST_RUN.

4. **Namespace testing**: Set up a test namespace and verify your XDP filter works correctly.

5. **Error injection**: Add code that sometimes fails and verify your error handling.

6. **Live debugging**: Attach to a running program and use bpftool to understand its state.
