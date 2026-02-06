# Learn eBPF in C as a Python Developer

A practical, hands-on guide that teaches you C and eBPF by building on what you already know as a Python developer.

## Who This Guide Is For

You are an experienced Python developer who needs to learn enough C to read, write, and understand eBPF programs. You don't need to become a C expert — you need to become dangerous enough to work with eBPF effectively.

This guide assumes you:

- Write Python professionally and are comfortable with its data model, standard library, and tooling
- Understand networking fundamentals (TCP/IP, sockets, ports, protocols)
- Have used Linux and are comfortable in a terminal
- Have little to no experience with C or systems programming

## What You'll Learn

**Part 1: C Fundamentals** — Every C concept is introduced by showing the Python equivalent first, then the C version. You'll learn types, pointers, memory, structs, bitwise operations, and the networking data structures that eBPF programs manipulate constantly.

**Part 2: eBPF Fundamentals** — How eBPF works under the hood: the architecture, program types, maps, helper functions, the verifier, and the two main toolchains (BCC for Python-friendly prototyping, libbpf for production).

**Part 3: Packet Interception & Manipulation** — The core material: intercepting syscalls, parsing packet headers, rewriting addresses and ports, and redirecting traffic. This is where C knowledge meets eBPF power.

**Part 4: Observability & Troubleshooting** — Using eBPF for tracing, metrics collection, and debugging. How to instrument systems and how to debug your own eBPF programs when things go wrong.

**Part 5: Security** — The eBPF security model, LSM hooks, seccomp-BPF, and hardening techniques.

**Projects** — Eight hands-on projects that build progressively from a simple syscall tracer to a full traffic-redirecting proxy. Early projects use BCC (Python) so you can leverage your existing skills; later projects graduate to libbpf (pure C) for production-grade code.

## How to Use This Guide

The guide is designed to be read sequentially — each chapter builds on the last. However, if you already know some C, you can skip ahead to Part 2. The projects are designed to be completed in order, as each one introduces new concepts that the next one builds upon.

Every code example is meant to be typed out and run, not just read. The fastest way to learn C and eBPF is to get your hands dirty.

## Quick Start

1. [Set up your development environment](getting-started/dev-environment.md)
2. [Run your first eBPF program](getting-started/hello-world.md)
3. Start with [Part 1: C Fundamentals](part1-c-fundamentals/index.md) or jump to [Part 2: eBPF Fundamentals](part2-ebpf-fundamentals/index.md) if you know C
