# Part 2: eBPF Fundamentals

You now have a working knowledge of C -- types, pointers, structs, bitwise operations, and the networking data structures that show up everywhere in systems programming. It is time to put that knowledge to use.

**eBPF** (extended Berkeley Packet Filter) lets you run sandboxed programs inside the Linux kernel without writing kernel modules or recompiling the kernel. It is one of the most significant developments in Linux in the past decade, and it is the reason you learned C in Part 1.

## What Part 2 Covers

This part takes you from "I know C" to "I understand how eBPF works end-to-end." By the time you finish, you will be able to:

- Explain what eBPF is, how it evolved from BPF, and why it matters
- Identify the right eBPF program type for a given task
- Use BPF maps to share data between kernel and userspace
- Call BPF helper functions from your programs
- Understand what the verifier checks and how to fix verifier errors
- Write eBPF programs using BCC (with a Python frontend)
- Write production-grade eBPF programs using libbpf and CO-RE
- Inspect and debug loaded eBPF programs with bpftool

## Chapter Overview

| Chapter | Topic | Key Takeaway |
|---------|-------|--------------|
| [Ch 10: What is eBPF?](ch10-what-is-ebpf.md) | Architecture & history | eBPF is a safe, in-kernel virtual machine |
| [Ch 11: Program Types](ch11-program-types.md) | Hook points & contexts | Different program types attach to different kernel subsystems |
| [Ch 12: BPF Maps](ch12-bpf-maps.md) | Shared data structures | Maps are how kernel eBPF programs talk to userspace |
| [Ch 13: BPF Helpers](ch13-bpf-helpers.md) | Kernel-provided API | Helper functions are your eBPF standard library |
| [Ch 14: The Verifier](ch14-the-verifier.md) | Safety guarantees | The verifier is the strictest code reviewer you will ever meet |
| [Ch 15: BCC & Python](ch15-bcc-python.md) | Python-friendly toolchain | BCC lets you prototype eBPF programs with a Python frontend |
| [Ch 16: libbpf & CO-RE](ch16-libbpf-and-co-re.md) | Production toolchain | libbpf + CO-RE is the standard for production eBPF |
| [Ch 17: bpftool](ch17-bpftool.md) | Inspection & debugging | bpftool is the Swiss army knife for eBPF |

## Prerequisites

Before starting Part 2, you should be comfortable with:

- **C types and variables** -- `int`, `__u32`, `__u64`, `char`, `void *`
- **Pointers and memory** -- dereferencing, pointer arithmetic, stack vs heap
- **Structs** -- defining them, accessing members, nested structs
- **Bitwise operations** -- AND, OR, shifts, masks (used heavily in packet parsing)
- **Networking structs** -- `struct ethhdr`, `struct iphdr`, `struct tcphdr`
- **The preprocessor** -- `#include`, `#define`, `#ifdef`
- **Build tools** -- invoking `clang`, basic Makefiles

If any of these feel shaky, revisit the relevant chapter in [Part 1](../part1-c-fundamentals/index.md).

## The Mental Model Shift

As a Python developer, you are used to working in userspace. Your code runs in a process, managed by the OS. You call library functions, make syscalls, and the kernel handles the rest.

eBPF flips that model. With eBPF, **your code runs inside the kernel itself** -- triggered by events like network packets arriving, syscalls being made, or functions being called. Your code sees data that userspace programs never see, and it runs with near-zero overhead because there is no context switch.

Think of it this way:

!!! tip "The Python Analogy"
    In Python, you might use a decorator to hook into a function call and run code before or after it. eBPF does the same thing, but for **kernel functions**. You attach a small program to a kernel event, and every time that event fires, your code runs -- inside the kernel, at native speed.

The trade-off is that kernel code must be **safe**. A bug in userspace crashes your process. A bug in the kernel crashes the entire machine. That is why eBPF has a verifier -- a static analyzer that rejects any program it cannot prove is safe. You will learn to love it (eventually).

## Two Toolchains, One Goal

You will learn two ways to write eBPF programs:

1. **BCC (BPF Compiler Collection)** -- A Python library that compiles C code at runtime and loads it into the kernel. Perfect for prototyping and one-off scripts. If you are a Python developer, this is where you will feel most at home.

2. **libbpf + CO-RE** -- A C library for loading pre-compiled eBPF programs. This is the production-standard approach. Programs are compiled once and run on any kernel version (that is the "CO-RE" -- Compile Once, Run Everywhere).

We cover both because they serve different purposes. BCC is great for learning and quick experiments. libbpf is what you deploy to production.

## Let's Go

Start with [Chapter 10: What is eBPF?](ch10-what-is-ebpf.md) to understand the architecture from the ground up.
