# Projects

This section contains eight hands-on projects that take you from a simple syscall tracer to a full traffic-redirecting proxy. Each project builds on the concepts from the previous one and from the chapters you have already read.

The projects follow a deliberate progression:

- **Projects 1--3** use **BCC (Python)** so you can leverage your existing Python skills while focusing on the eBPF kernel-side logic.
- **Projects 4--8** use **libbpf (C)** to give you production-grade experience with the standard eBPF toolchain.

## Project Map

| # | Project | What It Teaches | Toolchain | Prerequisites |
|---|---------|----------------|-----------|---------------|
| 01 | [Syscall Tracer](project01-syscall-tracer/index.md) | Kprobes, reading syscall args, BCC basics | BCC (Python) | Ch 1--9, Ch 10--15 |
| 02 | [Packet Counter](project02-packet-counter/index.md) | XDP programs, BPF maps, packet parsing | BCC (Python) | Ch 1--15, Ch 21--22 |
| 03 | [TCP Connect Logger](project03-tcp-connect-logger/index.md) | Ring buffers, structured events, network byte order | BCC (Python) | Ch 1--15, Ch 26, Ch 28 |
| 04 | [Header Inspector](project04-header-inspector/index.md) | TC programs, libbpf skeleton workflow, full packet parsing | libbpf (C) | Ch 1--17, Ch 20, Ch 22 |
| 05 | [Port Redirector](project05-port-redirector/index.md) | Packet modification, checksum recalculation | libbpf (C) | Ch 1--17, Ch 20, Ch 23 |
| 06 | [Connection Tracker](project06-connection-tracker/index.md) | sock_ops programs, connection state, hash maps | libbpf (C) | Ch 1--17, Ch 18--19 |
| 07 | [Traffic Monitor](project07-traffic-monitor/index.md) | Multiple program types, per-CPU maps, latency measurement | libbpf (C) | Ch 1--25, Projects 1--6 |
| 08 | [Proxy Redirect](project08-proxy-redirect/index.md) | cgroup hooks, connect() interception, socket cookies | libbpf (C) | All chapters, Projects 1--7 |

## Progression Diagram

```
 BCC (Python)                          libbpf (C)
 ───────────                           ──────────
 ┌──────────────┐
 │ 01: Syscall  │
 │    Tracer    │──┐
 └──────────────┘  │   ┌──────────────┐
                   ├──▶│ 02: Packet   │
                   │   │   Counter    │──┐
                   │   └──────────────┘  │   ┌──────────────┐
                   │                     ├──▶│ 03: TCP      │
                   │                     │   │   Connect    │──┐
                   │                     │   └──────────────┘  │
                   │                     │                     │
                   │   Transition to libbpf                    │
                   │   ─────────────────────                   │
                   │                     │   ┌──────────────┐  │
                   │                     └──▶│ 04: Header   │◀─┘
                   │                         │  Inspector   │──┐
                   │                         └──────────────┘  │
                   │                                           │
                   │   ┌──────────────┐   ┌──────────────┐    │
                   │   │ 05: Port     │◀──│ 06: Conn     │◀───┘
                   │   │  Redirector  │   │   Tracker    │
                   │   └──────┬───────┘   └──────┬───────┘
                   │          │                   │
                   │          ▼                   │
                   │   ┌──────────────┐           │
                   └──▶│ 07: Traffic  │◀──────────┘
                       │   Monitor   │
                       └──────┬───────┘
                              │
                              ▼
                       ┌──────────────┐
                       │ 08: Proxy    │  (capstone)
                       │   Redirect  │
                       └──────────────┘
```

## How to Work Through the Projects

1. **Read the prerequisites first.** Each project lists the chapters you should have read. Do not skip them -- the projects assume you understand those concepts.

2. **Type the code yourself.** Do not copy and paste. Typing forces you to read every line and understand what it does. This is especially important for eBPF programs where small details (byte order, bounds checks, verifier constraints) matter enormously.

3. **Run every program.** eBPF programs must run in a Linux environment with root privileges. If you have not set up your development environment yet, go back to [Development Environment](../getting-started/dev-environment.md).

4. **Do the exercises.** Each project ends with extension exercises that push you to apply what you learned in new ways. These are where the real learning happens.

5. **Debug your mistakes.** When the verifier rejects your program or your output is wrong, resist the urge to look at the solution immediately. The debugging process teaches you more than the working code.

!!! tip "Development Environment"
    All projects assume you are working in a Linux environment (native or VM) with:

    - Linux kernel 5.15 or later
    - BCC tools installed (for projects 1--3)
    - libbpf, clang, and bpftool installed (for projects 4--8)
    - Root privileges for loading eBPF programs

    See [Development Environment](../getting-started/dev-environment.md) for setup instructions.

!!! warning "Root Required"
    Every project in this section requires root privileges to load eBPF programs into the kernel. Run your programs with `sudo` or as the root user. In a production environment you would use capabilities (`CAP_BPF`, `CAP_NET_ADMIN`) for fine-grained access control.

## Start Building

Begin with [Project 1: Syscall Tracer](project01-syscall-tracer/index.md) -- the "hello world" of practical eBPF.
