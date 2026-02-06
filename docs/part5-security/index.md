# Part 5: Security

eBPF is a double-edged sword. It is one of the most powerful security tools available on Linux -- you can use it to enforce fine-grained security policies, filter system calls, monitor for intrusions, and lock down containers. But eBPF itself requires careful security consideration, because any technology that can run code inside the kernel is inherently sensitive.

Think of it this way: in Python, a security tool like a web application firewall runs in userspace, inspecting requests after they arrive. With eBPF, your security logic runs *inside the kernel*, intercepting operations before they complete. That is an enormous advantage for enforcement -- but it also means that a compromised or misconfigured eBPF program has kernel-level access to your system.

This part covers both sides of that coin.

## What Part 5 Covers

By the time you finish this part, you will be able to:

- Explain the eBPF security model: how the kernel protects itself from malicious or buggy eBPF programs
- Identify the Linux capabilities required to load different types of eBPF programs
- Write LSM (Linux Security Module) programs that enforce custom security policies at kernel decision points
- Understand seccomp-BPF and how container runtimes use it to restrict system calls
- Harden your eBPF deployments for production with least-privilege access, auditing, and resource controls

## Chapter Overview

| Chapter | Topic | Key Takeaway |
|---------|-------|--------------|
| [Ch 31: eBPF Security Model](ch31-ebpf-security-model.md) | Capabilities, trust, attack surface | The verifier is the sandbox, but capabilities control who gets in |
| [Ch 32: LSM Hooks](ch32-lsm-hooks.md) | Programmable security policies | eBPF + LSM = dynamic, fine-grained security enforcement |
| [Ch 33: Seccomp-BPF](ch33-seccomp-bpf.md) | System call filtering | Classic BPF filters restrict what syscalls a process can make |
| [Ch 34: Hardening](ch34-hardening.md) | Production security practices | Least privilege, auditing, and resource controls for eBPF |

## The Python Security Analogy

As a Python developer, you are familiar with security at the application layer: input validation, authentication, authorization, sandboxing untrusted code. You might use libraries like `cryptography` for encryption, or frameworks that provide CSRF protection and SQL injection prevention.

eBPF security operates at a completely different layer. Instead of protecting a web application from malicious users, you are protecting the **operating system** from malicious processes -- or protecting the eBPF subsystem itself from misuse.

| Python Security Concern | eBPF Security Equivalent |
|------------------------|--------------------------|
| Input validation | Verifier checking program safety |
| Authentication (who is the user?) | Linux capabilities (who can load programs?) |
| Authorization (what can they do?) | Program type restrictions, map permissions |
| Sandboxing (limiting untrusted code) | Seccomp-BPF, LSM hooks, cgroup isolation |
| Audit logging | bpftool inspection, BPF audit events |
| Dependency scanning | Verifying BPF program provenance |

## Prerequisites

Before starting Part 5, you should be comfortable with:

- **eBPF program types and maps** -- you need to know how programs are loaded, attached, and how they communicate with userspace (Part 2)
- **Packet interception** -- understanding of XDP, TC, and socket programs (Part 3) provides context for network security policies
- **Tracing concepts** -- familiarity with kprobes and tracepoints (Part 4) helps understand how eBPF can monitor security-relevant events
- **Linux fundamentals** -- a basic understanding of capabilities, namespaces, and cgroups will help, though we explain the relevant details as we go

!!! note "Security Is a Mindset, Not a Feature"
    Security is not something you bolt on at the end. The concepts in this part apply to everything you have learned so far. Every eBPF program you write should consider: who can load it, what data it can access, what happens if it misbehaves, and how you will audit it in production. Reading this part will change how you think about the programs you wrote in Parts 2 through 4.

## The Landscape

The eBPF security ecosystem is evolving rapidly. Major projects in this space include:

- **Cilium / Tetragon** -- Kubernetes-native security observability and enforcement using eBPF
- **Falco** -- Runtime security monitoring, with an eBPF driver for kernel event collection
- **KubeArmor** -- eBPF-based runtime security enforcement for containers
- **Tracee** -- Runtime security and forensics using eBPF

These tools all build on the primitives we cover in this part: the eBPF security model, LSM hooks, seccomp filtering, and hardening practices. Understanding the fundamentals will let you use these tools effectively -- or build your own.

## Let's Go

Start with [Chapter 31: eBPF Security Model](ch31-ebpf-security-model.md) to understand how the kernel protects itself from eBPF programs -- and how you control who gets to load them.
