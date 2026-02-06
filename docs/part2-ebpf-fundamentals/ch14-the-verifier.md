# Chapter 14: The Verifier

The verifier is the gatekeeper between your eBPF program and the kernel. It performs static analysis on your bytecode before the kernel allows it to run, checking that the program is safe. If the verifier rejects your program, it won't load — no exceptions.

This chapter explains what the verifier checks, how to read verifier errors, and how to write code that passes verification.

## Why the Verifier Exists

Running code in the kernel is inherently dangerous. A bug could:

- Crash the kernel (kernel panic)
- Read sensitive kernel memory
- Corrupt kernel data structures
- Infinite-loop and hang the system
- Access hardware incorrectly

Traditional kernel modules have these risks. eBPF programs don't — because the verifier proves they're safe before they run.

!!! tip "Python Comparison"
    Python has runtime safety: exceptions catch errors, garbage collection prevents memory bugs, and bounds checking prevents buffer overflows. C has none of this. The eBPF verifier provides compile-time (load-time) safety for C code running in the kernel.

## What the Verifier Checks

### 1. Program Terminates

The verifier ensures all execution paths reach a return statement within a bounded number of instructions.

```c
// REJECTED — infinite loop
while (1) {
    // ...
}

// ACCEPTED — bounded loop
#pragma unroll
for (int i = 0; i < 10; i++) {
    // ...
}
```

The verifier tracks the instruction count and rejects programs that could run too long.

### 2. No Out-of-Bounds Memory Access

Every pointer dereference must be provably within bounds.

```c
// REJECTED — no bounds check
SEC("xdp")
int bad(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    __u16 proto = eth->h_proto;  // Could be out of bounds!
    return XDP_PASS;
}

// ACCEPTED — bounds check before access
SEC("xdp")
int good(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    __u16 proto = eth->h_proto;  // Verifier knows this is safe
    return XDP_PASS;
}
```

### 3. No NULL Pointer Dereference

Map lookups can return NULL if the key isn't found. You must check before dereferencing.

```c
// REJECTED — might be NULL
__u64 *val = bpf_map_lookup_elem(&my_map, &key);
*val += 1;  // val might be NULL!

// ACCEPTED — NULL check first
__u64 *val = bpf_map_lookup_elem(&my_map, &key);
if (val) {
    *val += 1;
}
```

### 4. No Uninitialized Memory Reads

Stack variables must be written before being read.

```c
// REJECTED — reading uninitialized memory
int x;
if (x > 10) {  // x has garbage value
    // ...
}

// ACCEPTED — initialize first
int x = 0;
if (x > 10) {
    // ...
}
```

### 5. Valid Helper Calls

Only helpers available for the program type can be called, with correct argument types.

```c
// REJECTED in XDP — helper not available for this program type
SEC("xdp")
int bad(struct xdp_md *ctx) {
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));  // Not available in XDP!
    return XDP_PASS;
}
```

### 6. No Unreachable Code

All code paths must be reachable.

```c
// REJECTED — unreachable code after return
SEC("xdp")
int bad(struct xdp_md *ctx) {
    return XDP_PASS;
    int x = 5;  // Never reached!
}
```

### 7. Valid Return Values

Return values must be appropriate for the program type.

```c
// REJECTED — invalid XDP return value
SEC("xdp")
int bad(struct xdp_md *ctx) {
    return 42;  // Not a valid XDP action!
}

// ACCEPTED
SEC("xdp")
int good(struct xdp_md *ctx) {
    return XDP_PASS;  // Valid
}
```

## How the Verifier Works

The verifier simulates execution of your program, tracking the state of all registers and stack slots.

### Register Tracking

The BPF VM has 11 registers (R0-R10). The verifier tracks for each register:

- **Type**: scalar, pointer to map value, pointer to packet, etc.
- **Value range**: if known, the min/max possible values
- **Alignment**: for pointers

### Path Exploration

The verifier explores all possible execution paths. If your program has conditionals, it analyzes both branches.

```c
if (x > 10) {
    // Verifier analyzes this path with x > 10
} else {
    // Verifier analyzes this path with x <= 10
}
```

### State Pruning

To avoid exponential path explosion, the verifier prunes states it has already seen. This is why small changes can dramatically affect verification time.

## Reading Verifier Errors

When the verifier rejects your program, it outputs a log explaining why. Learning to read this is essential.

### Example Error

```
libbpf: prog 'my_xdp': BPF program load failed: Permission denied
libbpf: prog 'my_xdp': -- BEGIN PROG LOAD LOG --
0: (79) r2 = *(u64 *)(r1 +0)
1: (79) r3 = *(u64 *)(r1 +8)
2: (bf) r4 = r2
3: (07) r4 += 14
4: (2d) if r4 > r3 goto pc+5
 R1=ctx(off=0,imm=0) R2=pkt(off=0,r=14,imm=0) R3=pkt_end(off=0,imm=0) R4=pkt(off=14,r=14,imm=0)
5: (71) r5 = *(u8 *)(r2 +12)
 R2=pkt(off=0,r=14,imm=0) R3=pkt_end(off=0,imm=0)
6: (71) r0 = *(u8 *)(r2 +20)
invalid access to packet, off=20 size=1, R2(id=0,off=0,r=14)
R2 offset is outside of the packet
```

### Decoding the Error

1. **Instruction dump**: Each line shows an instruction number and the BPF assembly
2. **Register state**: `R2=pkt(off=0,r=14)` means R2 is a packet pointer, offset 0, with range checked up to 14 bytes
3. **Error message**: `invalid access to packet, off=20 size=1, R2(id=0,off=0,r=14)` — you're trying to read at offset 20, but only verified up to 14 bytes

### Common Error Messages

| Error | Meaning | Fix |
|-------|---------|-----|
| `invalid mem access` | Dereferencing unverified pointer | Add bounds check |
| `R0 !read_ok` | Reading NULL pointer | Add NULL check after map lookup |
| `invalid access to packet` | Packet access out of bounds | Check `data + offset <= data_end` |
| `unreachable instruction` | Dead code | Remove unreachable code |
| `back-edge from insn` | Backward jump (possible loop) | Use bounded loops or unroll |
| `invalid return value` | Wrong return type | Return valid values for program type |
| `cannot call helper` | Helper not allowed | Use helper appropriate for program type |

## Writing Verifier-Friendly Code

### Pattern 1: Always Bounds-Check Packet Access

```c
void *data = (void *)(long)ctx->data;
void *data_end = (void *)(long)ctx->data_end;

// Check for entire header before any access
struct ethhdr *eth = data;
if ((void *)(eth + 1) > data_end)
    return XDP_DROP;

// Now safe to access eth->h_proto, etc.

struct iphdr *ip = (void *)(eth + 1);
if ((void *)(ip + 1) > data_end)
    return XDP_DROP;

// Now safe to access ip->saddr, ip->daddr, etc.
```

### Pattern 2: Always NULL-Check Map Lookups

```c
__u64 *val = bpf_map_lookup_elem(&my_map, &key);
if (!val)
    return 0;  // Early return if not found
// Safe to use val
```

### Pattern 3: Initialize Stack Variables

```c
struct event e = {};  // Zero-initialize
// Or:
struct event e;
__builtin_memset(&e, 0, sizeof(e));
```

### Pattern 4: Use Bounded Loops

```c
// Verifier accepts this — known iteration count
#define MAX_ITERATIONS 100
for (int i = 0; i < MAX_ITERATIONS; i++) {
    // ...
    if (done)
        break;
}

// Or use bpf_loop (kernel 5.17+)
bpf_loop(count, callback_fn, ctx, 0);
```

### Pattern 5: Cast to Narrow Range

Sometimes you need to help the verifier track value ranges:

```c
// Verifier might not know that 'offset' is bounded
if (offset >= 0 && offset < 256) {
    // After this check, verifier knows offset is in [0, 255]
    __u8 *arr = (__u8 *)data + offset;
    // ...
}
```

### Pattern 6: Use `volatile` for Value Tracking

In some cases, `volatile` prevents compiler optimizations that confuse the verifier:

```c
volatile int idx = some_value;
if (idx < 0 || idx >= MAX_SIZE)
    return 0;
// Use idx — verifier tracks the bounds
```

## Verifier Limits

The verifier has resource limits:

| Limit | Value (typical) | Notes |
|-------|-----------------|-------|
| Max instructions | 1,000,000 | Total BPF instructions |
| Max states | 10,000 | Unique states during analysis |
| Max stack depth | 512 bytes | Per-program stack size |
| Max tail call depth | 33 | Nested tail calls |

If your program is too complex, you'll see errors like:

- `BPF program is too large`
- `verification time exceeded`
- `processed X insns ... exceeds limit`

### Reducing Verifier Complexity

1. **Split into multiple programs** with tail calls
2. **Simplify control flow** — fewer branches = fewer paths
3. **Use smaller loops** — unroll or reduce iteration count
4. **Inline helpers** instead of complex function calls

## Debugging Verification Failures

### Step 1: Get the Full Log

```bash
# With bpftool
sudo bpftool prog load myprogram.bpf.o /sys/fs/bpf/test 2>&1

# With libbpf (set log level)
struct bpf_object_load_opts opts = {
    .sz = sizeof(opts),
    .log_level = 1,  // or 2 for verbose
};
```

### Step 2: Find the Failing Instruction

The error message includes the instruction number. Map it back to your C code using:

```bash
llvm-objdump -S -d myprogram.bpf.o
```

This shows C source alongside BPF assembly.

### Step 3: Check Register State

The log shows register types. Look for:

- `scalar` — verifier doesn't know it's a valid pointer
- `pkt(off=X,r=Y)` — packet pointer with offset X, bounds checked to Y
- `map_value` — pointer from map lookup

### Step 4: Add Missing Checks

Usually the fix is adding a bounds check or NULL check that makes the access provably safe.

## Exercises

1. **Trigger verification failure**: Write a program that accesses packet data without a bounds check. Read and understand the verifier error.

2. **Fix NULL deref**: Write a program with a map lookup that forgets to NULL-check. Fix it and verify it loads.

3. **Bounded loop practice**: Write a loop that iterates over packet bytes. Start with `for (int i = 0; i < len; i++)` (will fail) and fix it to use a bounded iteration.

4. **Verifier log levels**: Load the same program with log level 1 vs 2. Compare the output.

5. **Instruction limit**: Write a program complex enough to hit verifier limits (hint: many nested conditionals). Then refactor to reduce complexity.

6. **CO-RE and the verifier**: Use `bpf_core_read()` to read a kernel struct field. Observe how it affects verification compared to `bpf_probe_read_kernel()`.
