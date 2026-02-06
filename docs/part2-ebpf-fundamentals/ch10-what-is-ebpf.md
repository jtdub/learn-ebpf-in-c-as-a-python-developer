# Chapter 10: What is eBPF?

eBPF is a technology that lets you run sandboxed programs inside the Linux kernel without modifying kernel source code or loading kernel modules. It is the most significant change to how we interact with the Linux kernel in the past decade.

In this chapter, you will learn where eBPF came from, how it works architecturally, and why it exists. By the end, you will understand the full lifecycle of an eBPF program from C source code to running in the kernel.

## A Brief History: From BPF to eBPF

### The Original BPF (1992)

BPF -- Berkeley Packet Filter -- was created in 1992 by Steven McCanne and Van Jacobson at Lawrence Berkeley National Laboratory. Its original purpose was narrow: efficiently filter network packets in the kernel so that tools like `tcpdump` did not have to copy every packet to userspace just to decide which ones to keep.

The key insight was simple but powerful: instead of filtering packets in userspace (which requires a costly context switch per packet), run a small **filter program** in the kernel. BPF defined a tiny virtual machine with a small instruction set, two registers, and a scratch memory area. You wrote a filter in BPF bytecode, the kernel loaded it, and packets were filtered at kernel speed.

```
# Classic BPF: tcpdump compiles this filter to BPF bytecode
tcpdump -d 'tcp port 80'
```

This was classic BPF -- a packet filter, nothing more.

### The Extension: eBPF (2014)

In 2014, Alexei Starovoitov submitted patches to the Linux kernel that dramatically expanded BPF into what we now call **eBPF** (extended BPF). The changes were sweeping:

| Feature | Classic BPF | eBPF |
|---------|------------|------|
| Registers | 2 (32-bit) | 11 (64-bit: R0-R10) |
| Instruction set | ~30 instructions | ~100+ instructions |
| Stack size | 16 slots | 512 bytes |
| Maps (shared data) | No | Yes |
| Program types | Packet filter only | Dozens (networking, tracing, security, ...) |
| Helper functions | No | Yes (kernel-provided API) |
| JIT compilation | Limited | Full JIT for major architectures |
| Tail calls | No | Yes |

eBPF turned a packet filter into a **general-purpose in-kernel virtual machine**. You can now attach eBPF programs to almost any kernel event -- network packets, syscalls, function calls, tracepoints, security hooks, and more.

!!! note "eBPF vs BPF"
    In modern usage, "BPF" and "eBPF" are used interchangeably to mean the extended version. Nobody writes classic BPF anymore. When you see "BPF" in code (like `BPF_MAP_TYPE_HASH` or `bpf()` syscall), it refers to eBPF. This guide uses "eBPF" for the technology and "BPF" in code identifiers where that is the actual name.

## Architecture Overview

eBPF has four main components:

```
┌─────────────────────────────────────────────────────┐
│                    USERSPACE                         │
│                                                     │
│   ┌──────────┐    ┌──────────┐    ┌──────────────┐  │
│   │  C Source │───▶│  Clang/  │───▶│ BPF Bytecode │  │
│   │  (.bpf.c)│    │  LLVM    │    │   (.o ELF)   │  │
│   └──────────┘    └──────────┘    └──────┬───────┘  │
│                                          │          │
│   ┌──────────────────────────────────────┘          │
│   │  bpf() syscall                                  │
├───┼─────────────────────────────────────────────────┤
│   ▼              KERNEL                              │
│   ┌──────────┐    ┌──────────┐    ┌──────────────┐  │
│   │ Verifier │───▶│   JIT    │───▶│  Native Code │  │
│   │ (safety  │    │ Compiler │    │ (attached to │  │
│   │  check)  │    │          │    │   hook)      │  │
│   └──────────┘    └──────────┘    └──────────────┘  │
│                                                     │
│   ┌──────────────────────────────────────────────┐  │
│   │              BPF Maps                         │  │
│   │   (shared data: kernel ←→ userspace)         │  │
│   └──────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

### 1. The Bytecode and Instruction Set

eBPF programs compile to a platform-independent bytecode, much like Python compiles to `.pyc` bytecode or Java compiles to JVM bytecode. The eBPF instruction set has:

- **11 registers** (R0-R10): R0 is the return value, R1-R5 are function arguments, R6-R9 are callee-saved, R10 is the read-only frame pointer (stack)
- **64-bit registers**: Each register is 64 bits wide
- **Instructions**: Arithmetic, jumps, memory loads/stores, function calls
- **512-byte stack**: Small but sufficient for local variables

!!! tip "Python Comparison: Bytecode VMs"
    Python compiles `.py` files to bytecode that runs on the CPython VM. eBPF compiles `.bpf.c` files to bytecode that runs in the kernel's BPF VM. The concepts are remarkably similar:

    | Concept | Python | eBPF |
    |---------|--------|------|
    | Source | `.py` | `.bpf.c` |
    | Bytecode | `.pyc` | BPF ELF `.o` |
    | VM | CPython VM | BPF VM / JIT |
    | Inspection | `dis.dis()` | `bpftool prog dump` |
    | Safety | Runtime exceptions | Static verification before load |

Here is what eBPF bytecode looks like (you never write this by hand -- clang generates it):

```
; BPF assembly for a simple program that returns 0
0: r0 = 0          ; set return value to 0
1: exit             ; return from program
```

Compare to Python bytecode:

```python
import dis
def f():
    return 0
dis.dis(f)
#   0 LOAD_CONST   0 (0)
#   2 RETURN_VALUE
```

Both are register-based (eBPF) or stack-based (CPython) instruction sets that a virtual machine executes. The critical difference is that eBPF bytecode is **statically verified before it runs** -- there are no runtime exceptions, no try/except, no error recovery. If the verifier cannot prove your program is safe, it will not load.

### 2. The Verifier

The verifier is a static analyzer that examines every possible execution path of your eBPF program before it is allowed to run. It ensures:

- The program **terminates** (no infinite loops)
- All **memory accesses** are within bounds
- All **map lookups** have their return values null-checked
- The **stack** does not exceed 512 bytes
- No **unreachable code** exists
- All **helper function calls** are valid for the program type

We cover the verifier in depth in [Chapter 14](ch14-the-verifier.md). For now, just know that it exists and it is strict.

### 3. The JIT Compiler

After the verifier approves a program, the JIT (Just-In-Time) compiler translates BPF bytecode into native machine code for the host architecture (x86_64, ARM64, etc.). This means eBPF programs run at **near-native speed** -- there is no interpreter overhead.

```
BPF bytecode  →  JIT  →  x86_64 machine code
                         (runs at native speed)
```

!!! note
    JIT compilation is enabled by default on modern kernels. You can check with:
    ```bash
    cat /proc/sys/net/core/bpf_jit_enable
    # 1 = enabled, 0 = disabled
    ```

### 4. BPF Maps

Maps are key-value data structures that live in the kernel and are accessible from both eBPF programs (kernel side) and userspace programs. They are the primary mechanism for:

- **Passing data** from kernel eBPF programs to userspace
- **Sharing state** between multiple eBPF programs
- **Configuring** eBPF program behavior from userspace

We cover maps in detail in [Chapter 12](ch12-bpf-maps.md).

## The Kernel/Userspace Split

Every eBPF application has two parts:

**Kernel side** (the eBPF program):

- Written in restricted C
- Compiled to BPF bytecode
- Runs inside the kernel
- Triggered by events (packets, syscalls, function calls)
- Limited to ~1 million instructions (varies by kernel version)
- Cannot call arbitrary kernel functions -- only BPF helpers
- Cannot allocate heap memory
- Stack limited to 512 bytes

**Userspace side** (the loader/reader):

- Written in C (libbpf), Python (BCC), Go, Rust, or any language
- Loads the eBPF program into the kernel via the `bpf()` syscall
- Reads data from BPF maps
- Manages the eBPF program lifecycle (attach, detach, unload)

=== "Python"

    ```python
    # In Python, everything runs in one place (userspace)
    import socket

    # Your code processes packets in userspace
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    while True:
        packet = sock.recv(65535)
        # Parse packet, make decisions...
        # Every packet requires a context switch from kernel to userspace
    ```

=== "C"

    ```c
    // In eBPF, your code runs IN the kernel
    // No context switch -- you see the packet where it lives

    // Kernel side (runs in kernel context)
    SEC("xdp")
    int process_packet(struct xdp_md *ctx) {
        // This code runs at the earliest possible point in the
        // network stack, before the kernel allocates an sk_buff.
        // No context switch, no copying to userspace.
        void *data = (void *)(long)ctx->data;
        void *data_end = (void *)(long)ctx->data_end;

        struct ethhdr *eth = data;
        if ((void *)(eth + 1) > data_end)
            return XDP_PASS;

        // Make decisions at kernel speed
        return XDP_PASS;
    }
    ```

## Why eBPF Exists: Safe Kernel Extensibility

Before eBPF, if you wanted to add custom logic to the kernel, you had three options:

1. **Modify the kernel source and recompile** -- Impractical for most use cases. Requires maintaining a fork.

2. **Write a kernel module** -- Powerful but dangerous. A bug in a kernel module can crash the system, corrupt memory, or create security holes. No safety guarantees.

3. **Do it in userspace** -- Safe but slow. Every packet or event requires a context switch between kernel and userspace.

eBPF gives you a fourth option: **run custom code in the kernel with safety guarantees**. The verifier ensures your code cannot crash the kernel, access memory it should not, or run forever. You get kernel-speed performance with userspace-level safety.

!!! tip "Think of it Like a Plugin System"
    If the Linux kernel were a web framework, eBPF would be its plugin system. You write small functions that hook into specific events, the framework (verifier) checks that your plugins are well-behaved, and then your code runs as part of the framework's processing pipeline. The framework (kernel) stays stable while your plugins add custom behavior.

## The eBPF Program Lifecycle

Here is the complete lifecycle of an eBPF program, from source code to running in the kernel:

### Step 1: Write the C Source

```c
// hello.bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int hello(void *ctx) {
    bpf_printk("Hello, eBPF! A process called execve.\n");
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

Key elements:

- `#include <linux/bpf.h>` -- Kernel BPF definitions
- `#include <bpf/bpf_helpers.h>` -- Helper function declarations
- `SEC("tracepoint/...")` -- Tells the loader what hook point to attach to
- `bpf_printk` -- A helper function for debug output (writes to `/sys/kernel/debug/tracing/trace_pipe`)
- `char LICENSE[]` -- Required. Many helpers require a GPL-compatible license.

### Step 2: Compile to BPF Bytecode

```bash
clang -O2 -target bpf -c hello.bpf.c -o hello.bpf.o
```

This produces an ELF object file containing BPF bytecode. The `-target bpf` flag tells clang to emit BPF instructions instead of x86_64.

### Step 3: Load into the Kernel

The userspace program calls the `bpf()` syscall (usually via a library like libbpf) to load the bytecode into the kernel.

```c
// Simplified -- libbpf handles this for you
int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
```

### Step 4: Verifier Checks

The kernel's verifier analyzes every possible execution path:

```
Verifier analysis:
  0: (b7) r0 = 0          ; safe: sets register
  1: (85) call bpf_printk  ; safe: valid helper for this program type
  2: (b7) r0 = 0          ; safe: sets return value
  3: (95) exit             ; safe: program terminates

  processed 4 insns
```

If the verifier rejects the program, you get an error message explaining why.

### Step 5: JIT Compiles to Native Code

The JIT compiler translates verified BPF bytecode into native machine instructions.

### Step 6: Attach to Hook Point

The program is attached to its hook point (in this case, the `sys_enter_execve` tracepoint). Every time any process on the system calls `execve()`, our eBPF program runs.

### Step 7: Runs on Events

```bash
# In one terminal, read the output
sudo cat /sys/kernel/debug/tracing/trace_pipe

# In another terminal, trigger the event
ls  # ls calls execve, which triggers our eBPF program

# Output:
# <...>-12345 [002] d... 12345.678: bpf_trace_printk: Hello, eBPF! A process called execve.
```

## The bpf() Syscall

All eBPF operations go through a single syscall: `bpf()`. It handles everything:

```c
#include <linux/bpf.h>

int bpf(int cmd, union bpf_attr *attr, unsigned int size);
```

Key commands:

| Command | Purpose |
|---------|---------|
| `BPF_PROG_LOAD` | Load an eBPF program into the kernel |
| `BPF_MAP_CREATE` | Create a new BPF map |
| `BPF_MAP_LOOKUP_ELEM` | Look up a value in a map |
| `BPF_MAP_UPDATE_ELEM` | Insert or update a map entry |
| `BPF_MAP_DELETE_ELEM` | Delete a map entry |
| `BPF_PROG_ATTACH` | Attach a program to a hook |
| `BPF_PROG_DETACH` | Detach a program from a hook |
| `BPF_OBJ_PIN` | Pin a program or map to the BPF filesystem |
| `BPF_OBJ_GET` | Retrieve a pinned program or map |

You rarely call `bpf()` directly. Libraries like libbpf and BCC wrap it for you.

## eBPF vs Python: A Comparison of Execution Models

Let's compare how Python and eBPF handle a common task: counting TCP connections.

=== "Python"

    ```python
    # Python approach: capture in userspace
    import socket
    import struct
    from collections import Counter

    counts = Counter()

    # Raw socket to see TCP packets
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    while True:
        packet, addr = sock.recvfrom(65535)
        # Parse IP header (skip first 20 bytes for simplicity)
        tcp_header = packet[20:40]
        src_port, dst_port, seq, ack, offset_flags = struct.unpack(
            '!HHLLH', tcp_header[:14]
        )
        flags = offset_flags & 0x3F
        is_syn = flags & 0x02

        if is_syn and not (flags & 0x10):  # SYN but not ACK
            counts[addr[0]] += 1
            print(f"New TCP connection from {addr[0]} (total: {counts[addr[0]]})")
    ```

    **Problem**: Every packet is copied from kernel to userspace. On a busy server, this is slow and wasteful.

=== "C"

    ```c
    // eBPF approach: count in the kernel, read from userspace
    // Kernel side (hello_tcp.bpf.c)
    #include <linux/bpf.h>
    #include <bpf/bpf_helpers.h>

    struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 10240);
        __type(key, __u32);    // source IP
        __type(value, __u64);  // count
    } tcp_connects SEC(".maps");

    SEC("tracepoint/sock/inet_sock_set_state")
    int count_connects(void *ctx) {
        // ... parse tracepoint arguments, increment counter in map
        return 0;
    }

    char LICENSE[] SEC("license") = "GPL";
    ```

    **Advantage**: The counting happens inside the kernel. Only the aggregated counts are read from userspace. No per-packet context switch.

## What eBPF Cannot Do

eBPF is powerful but deliberately limited:

- **No unbounded loops** -- Every loop must have a known bound (relaxed in newer kernels with bounded loop support)
- **No heap allocation** -- You cannot call `malloc()`. You use maps or the 512-byte stack.
- **No arbitrary kernel function calls** -- Only approved BPF helper functions
- **No floating-point math** -- The BPF instruction set has no floating-point operations
- **Limited stack** -- 512 bytes maximum
- **Limited program size** -- ~1 million instructions (increased from 4096 in older kernels)
- **No sleeping** -- eBPF programs cannot block or sleep (with limited exceptions for sleepable BPF programs in newer kernels)

These restrictions exist because eBPF code runs in the kernel. Every restriction maps to a safety property.

## Summary

- eBPF evolved from a simple packet filter (BPF, 1992) into a general-purpose in-kernel VM (eBPF, 2014)
- Programs are written in C, compiled to bytecode, verified for safety, JIT-compiled, and attached to kernel hook points
- The verifier ensures safety; the JIT compiler ensures performance
- BPF maps are the communication channel between kernel and userspace
- eBPF gives you kernel-speed processing with safety guarantees

## Exercises

1. **Explore the BPF filesystem**: Run `sudo mount -t bpf bpf /sys/fs/bpf` (if not already mounted), then `ls /sys/fs/bpf/`. Are there any pinned programs or maps on your system? What do you see?

2. **Inspect Python bytecode**: Use `dis.dis()` to disassemble a simple Python function. Compare the concepts (opcodes, operands, stack/register operations) to what you learned about BPF bytecode. Write down three similarities and three differences.

3. **Check your kernel's BPF capabilities**: Run the following commands and note what you find:
    ```bash
    # JIT status
    cat /proc/sys/net/core/bpf_jit_enable
    # Kernel version (eBPF features depend on this)
    uname -r
    # BPF syscall availability
    grep bpf /proc/kallsyms | head -5
    ```

4. **Trace the lifecycle**: Using the `hello.bpf.c` example from this chapter, write out each step of the lifecycle (compile, load, verify, JIT, attach, run) and annotate what happens at each step. What could go wrong at each stage?

5. **Research exercise**: Look up the kernel version requirements for three eBPF features that interest you (e.g., ring buffer maps, BTF, bounded loops). Which kernel version does your system run? Which features are available to you?
