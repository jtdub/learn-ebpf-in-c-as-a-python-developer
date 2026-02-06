# Part 1: C Fundamentals for eBPF

You know Python. You think in Python. Now you need to write C — not because you want to become a systems programmer, but because eBPF programs are written in a restricted subset of C, and there is no way around it.

The good news: you don't need to learn all of C. eBPF uses a surprisingly small slice of the language. You won't be writing dynamic memory allocators or building linked lists. You will be declaring fixed-size structs, parsing packet headers with pointer arithmetic, and using bitwise operations to check flags. That's the job.

## Why C for eBPF?

eBPF programs compile to a special bytecode that runs inside a virtual machine in the Linux kernel. The only language with mature, production-grade support for targeting this bytecode is C (compiled with clang). There are experimental Rust frontends, but C remains the standard.

As a Python developer, you might wonder: "Can't I just use BCC and write everything in Python?" You can write the **userspace loader** in Python with BCC, but the eBPF program itself — the part that runs inside the kernel — is always C. Even with BCC, you embed C code as a string inside your Python script.

```python
# BCC example — the C code is unavoidable
from bcc import BPF

program = r"""
int trace_connect(struct pt_regs *ctx) {
    // This is C, not Python. You must understand it.
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_trace_printk("connect from pid %d\n", pid);
    return 0;
}
"""

b = BPF(text=program)
```

## What This Part Covers

Each chapter introduces a C concept by showing you the Python equivalent first, then the C version. We focus exclusively on the C features that matter for eBPF:

| Chapter | Topic | Why It Matters for eBPF |
|---------|-------|------------------------|
| [Ch 1: Types & Variables](ch01-types-and-variables.md) | `int`, `char`, `__u32`, `__u64`, casting | Every eBPF map key and value has a fixed type. You must understand type sizes. |
| [Ch 2: Pointers & Memory](ch02-pointers-and-memory.md) | `*`, `&`, stack vs heap, NULL | Parsing packets means pointer arithmetic. The verifier checks every pointer access. |
| [Ch 3: Structs & Unions](ch03-structs-and-unions.md) | `struct`, memory layout, padding | Network headers, map values, and BPF contexts are all structs. |
| [Ch 4: Arrays & Strings](ch04-arrays-and-strings.md) | Fixed-size arrays, C strings, bounds checking | Buffer overflows crash kernels. The verifier enforces bounds checks. |
| [Ch 5: Control Flow & Functions](ch05-control-flow-and-functions.md) | Loops, `switch`, `static inline` | eBPF requires bounded loops and inlined functions. |
| [Ch 6: Bitwise Operations](ch06-bitwise-operations.md) | `&`, `|`, `^`, `<<`, `>>` | TCP flags, IP header fields, protocol parsing — all bitwise. |
| [Ch 7: Preprocessor & Macros](ch07-preprocessor-and-macros.md) | `#define`, `#include`, `SEC()` | Every eBPF program uses macros for section annotations and map definitions. |
| [Ch 8: Networking Structs](ch08-networking-structs.md) | `iphdr`, `tcphdr`, byte order | The core data structures you will parse and manipulate. |
| [Ch 9: Build Tools](ch09-build-tools.md) | Makefiles, clang flags | How to compile eBPF programs and automate builds. |

## What We Skip

This is not a complete C tutorial. We deliberately skip topics that don't matter for eBPF development:

- **Dynamic memory allocation** (`malloc`/`free`) — eBPF programs cannot allocate heap memory
- **File I/O** (`fopen`, `fread`) — eBPF programs cannot access the filesystem
- **Standard library** (`stdio.h`, `stdlib.h`) — most of it is unavailable in kernel space
- **Complex data structures** (linked lists, trees) — eBPF uses maps for data storage, not custom data structures
- **Multi-file compilation and linking** — eBPF programs are typically single-file
- **Object-oriented patterns** — there are no classes in C, and eBPF doesn't need them

## The Python-to-C Mental Model

Here is the core mental shift you need to make:

| In Python... | In C... |
|-------------|---------|
| Everything is an object with a type, methods, and metadata | Everything is bytes in memory with a known size |
| Variables are references (names pointing to objects) | Variables are labeled memory locations |
| Memory is managed for you (garbage collection) | You manage memory explicitly (but eBPF uses only stack memory) |
| Types are checked at runtime (dynamic typing) | Types are checked at compile time (static typing) |
| Errors raise exceptions | Errors are return codes (no exceptions in C) |
| You import modules | You `#include` header files (copy-paste at compile time) |
| Indentation defines scope | Curly braces `{}` define scope |

!!! tip "The Most Important Mindset Shift"
    In Python, you think about **what data means** (it's a string, it's a list of users, it's an HTTP response). In C, you think about **how data is laid out in memory** (it's 4 bytes at offset 12, it's a 20-byte struct starting at this pointer). For eBPF, you need both perspectives: you're parsing network packets (meaningful data) by reading specific bytes at specific memory offsets (physical layout).

## How to Work Through This Part

1. **Read each chapter in order** — they build on each other
2. **Type out every code example** — don't just read them
3. **Do the exercises** — they're designed to build eBPF-relevant muscle memory
4. **Refer back often** — you'll return to these chapters when writing real eBPF programs

If you already know C, skim Part 1 for the eBPF-specific notes (marked with admonitions) and move to [Part 2: eBPF Fundamentals](../part2-ebpf-fundamentals/index.md).

Let's start with [Chapter 1: Types & Variables](ch01-types-and-variables.md).
