# Resources

A curated collection of resources for learning C, eBPF, and systems programming.

## Official Documentation

### eBPF

| Resource | Description |
|----------|-------------|
| [eBPF.io](https://ebpf.io/) | Official eBPF project website with tutorials and documentation |
| [Kernel BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/) | Linux kernel BPF documentation |
| [libbpf Documentation](https://libbpf.readthedocs.io/) | Official libbpf library documentation |
| [BCC Reference Guide](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md) | BCC tools reference |
| [XDP Tutorial](https://github.com/xdp-project/xdp-tutorial) | Comprehensive XDP tutorial with exercises |

### C Language

| Resource | Description |
|----------|-------------|
| [cppreference.com](https://en.cppreference.com/w/c) | Comprehensive C language reference |
| [GNU C Manual](https://www.gnu.org/software/gnu-c-manual/) | GNU C programming documentation |
| [C Standard Library](https://en.cppreference.com/w/c/header) | Standard library headers reference |

## Books

### eBPF Books

| Book | Author | Notes |
|------|--------|-------|
| *Learning eBPF* | Liz Rice | Excellent introduction with hands-on examples |
| *Linux Observability with BPF* | David Calavera, Lorenzo Fontana | Focus on tracing and monitoring |
| *BPF Performance Tools* | Brendan Gregg | Comprehensive performance analysis guide |
| *What is eBPF?* | Liz Rice | Short introduction (free PDF available) |

### C Programming Books

| Book | Author | Notes |
|------|--------|-------|
| *The C Programming Language* | Kernighan & Ritchie | The classic "K&R" book |
| *Modern C* | Jens Gustedt | Free PDF, covers C17 |
| *C Programming: A Modern Approach* | K.N. King | Comprehensive textbook |
| *Expert C Programming* | Peter van der Linden | Deep secrets of C |

### Linux/Systems Books

| Book | Author | Notes |
|------|--------|-------|
| *Linux Kernel Development* | Robert Love | Kernel internals |
| *Understanding the Linux Kernel* | Bovet & Cesati | Detailed kernel analysis |
| *The Linux Programming Interface* | Michael Kerrisk | Comprehensive system programming |

## Online Courses and Tutorials

### eBPF

- [eBPF and XDP Course](https://github.com/xdp-project/bpf-next) - Kernel developers' tutorial
- [Isovalent eBPF Labs](https://isovalent.com/labs/) - Interactive browser-based labs
- [Cilium Getting Started](https://docs.cilium.io/en/stable/gettingstarted/) - eBPF-based networking

### C Programming

- [Learn-C.org](https://www.learn-c.org/) - Interactive C tutorial
- [CS50](https://cs50.harvard.edu/x/) - Harvard's intro CS course (C-based)
- [Beej's Guide to C](https://beej.us/guide/bgc/) - Free online guide

## Tools

### Development

| Tool | Purpose | Installation |
|------|---------|--------------|
| **bpftool** | BPF inspection and management | `apt install linux-tools-$(uname -r)` |
| **llvm/clang** | BPF compilation | `apt install clang llvm` |
| **libbpf** | BPF loading library | `apt install libbpf-dev` |
| **bcc-tools** | Pre-built BPF tools | `apt install bcc-tools` |
| **bpftrace** | High-level tracing | `apt install bpftrace` |

### Debugging

| Tool | Purpose | Usage |
|------|---------|-------|
| **gdb** | C debugging | `gdb ./program` |
| **valgrind** | Memory checking | `valgrind ./program` |
| **strace** | System call tracing | `strace ./program` |
| **perf** | Performance analysis | `perf record ./program` |

### Network Testing

| Tool | Purpose | Example |
|------|---------|---------|
| **tcpdump** | Packet capture | `tcpdump -i eth0` |
| **wireshark** | Packet analysis | GUI tool |
| **netcat** | Network testing | `nc -l 8080` |
| **curl** | HTTP testing | `curl localhost:8080` |
| **iperf3** | Bandwidth testing | `iperf3 -s` / `iperf3 -c host` |

## GitHub Repositories

### Example Code

| Repository | Description |
|------------|-------------|
| [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap) | Modern BPF application templates |
| [bcc/tools](https://github.com/iovisor/bcc/tree/master/tools) | Production BCC tools |
| [bpftrace/tools](https://github.com/bpftrace/bpftrace/tree/master/tools) | bpftrace one-liners |
| [xdp-tools](https://github.com/xdp-project/xdp-tools) | XDP utilities and examples |

### Libraries and Frameworks

| Repository | Description |
|------------|-------------|
| [libbpf](https://github.com/libbpf/libbpf) | Official BPF loading library |
| [bcc](https://github.com/iovisor/bcc) | BPF Compiler Collection |
| [cilium/ebpf](https://github.com/cilium/ebpf) | Pure Go eBPF library |
| [libbpf-rs](https://github.com/libbpf/libbpf-rs) | Rust bindings for libbpf |
| [aya](https://github.com/aya-rs/aya) | Pure Rust eBPF library |

### Real-World Projects

| Project | Description |
|---------|-------------|
| [Cilium](https://github.com/cilium/cilium) | eBPF-based networking |
| [Falco](https://github.com/falcosecurity/falco) | Runtime security |
| [Tetragon](https://github.com/cilium/tetragon) | Security observability |
| [Pixie](https://github.com/pixie-io/pixie) | Auto-instrumentation |
| [Katran](https://github.com/facebookincubator/katran) | Network load balancer |

## Community

### Mailing Lists and Forums

- [BPF Mailing List](https://lore.kernel.org/bpf/) - Kernel BPF development
- [eBPF Slack](https://ebpf.io/slack) - Community chat
- [Stack Overflow [ebpf]](https://stackoverflow.com/questions/tagged/ebpf) - Q&A

### Conferences and Talks

| Event | Focus |
|-------|-------|
| [eBPF Summit](https://ebpf.io/summit-2024/) | Annual eBPF conference |
| [Linux Plumbers Conference](https://lpc.events/) | BPF/Networking track |
| [KubeCon](https://www.cncf.io/kubecon-cloudnativecon-events/) | Cloud native + eBPF |

### Blogs

| Blog | Focus |
|------|-------|
| [Brendan Gregg's Blog](https://www.brendangregg.com/blog/) | Performance, tracing |
| [Cloudflare Blog](https://blog.cloudflare.com/tag/ebpf/) | eBPF at scale |
| [Isovalent Blog](https://isovalent.com/blog/) | Cilium, eBPF |
| [Elastic Blog](https://www.elastic.co/blog/tag/ebpf) | Observability |

## Kernel Source References

### Key Files

| Path | Contents |
|------|----------|
| `include/linux/bpf.h` | Core BPF definitions |
| `include/uapi/linux/bpf.h` | Userspace BPF API |
| `kernel/bpf/` | BPF subsystem implementation |
| `net/core/filter.c` | Socket and network BPF |
| `tools/lib/bpf/` | libbpf source |
| `samples/bpf/` | Kernel BPF samples |
| `tools/testing/selftests/bpf/` | BPF self-tests (great examples) |

### Browse Online

- [Elixir Cross Referencer](https://elixir.bootlin.com/linux/latest/source) - Searchable kernel source
- [GitHub Linux Kernel](https://github.com/torvalds/linux) - Official mirror

## Cheat Sheets

### Quick References

- [eBPF Cheatsheet](./cheatsheet.md) - This guide's reference
- [BCC Reference](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md)
- [bpftrace Reference](https://github.com/bpftrace/bpftrace/blob/master/docs/reference_guide.md)
- [C Quick Reference](https://www.cs.bu.edu/teaching/c/file-io/intro/)

## Podcasts and Videos

### YouTube Channels

| Channel | Content |
|---------|---------|
| [Brendan Gregg](https://www.youtube.com/user/brendangregg) | Performance talks |
| [CNCF](https://www.youtube.com/c/cloudnativefdn) | KubeCon talks |
| [Linux Foundation](https://www.youtube.com/c/LinuxfoundationOrg) | Conference recordings |

### Notable Talks

- "BPF: Tracing and More" - Brendan Gregg
- "A Beginner's Guide to eBPF" - Liz Rice
- "eBPF and Kubernetes" - Various KubeCon talks

## Environment Setup

### VM Images

| Distribution | Notes |
|--------------|-------|
| [Ubuntu 22.04+](https://ubuntu.com/download) | Best for beginners, good BPF support |
| [Fedora 38+](https://fedoraproject.org/) | Latest kernel features |
| [Debian 12+](https://www.debian.org/) | Stable, good for production |

### Cloud Options

- **Google Cloud** - Free tier with nested virtualization
- **AWS EC2** - Metal instances for best BPF support
- **DigitalOcean** - Simple VMs, works well
- **Multipass** - Local Ubuntu VMs (`multipass launch`)

### Container Development

```bash
# Quick development container
docker run -it --privileged \
    -v /sys/kernel/debug:/sys/kernel/debug \
    -v /sys/fs/bpf:/sys/fs/bpf \
    --pid=host \
    ubuntu:22.04

# Inside container
apt update && apt install -y \
    clang llvm libbpf-dev \
    linux-tools-generic bpftool
```

## Further Learning Path

### Beginner

1. Complete this guide's C fundamentals (Part 1)
2. Run through eBPF fundamentals (Part 2)
3. Build Projects 1-3 with BCC
4. Read *Learning eBPF* by Liz Rice

### Intermediate

1. Complete packet interception (Part 3)
2. Master observability (Part 4)
3. Build Projects 4-6 with libbpf
4. Read *BPF Performance Tools*

### Advanced

1. Study security topics (Part 5)
2. Complete Projects 7-8
3. Explore kernel source
4. Contribute to BCC/libbpf

## Getting Help

### Before Asking

1. Check kernel version: `uname -r`
2. Check verifier error carefully
3. Search existing issues
4. Prepare minimal reproduction

### Where to Ask

- **GitHub Issues** - For specific tool bugs
- **Stack Overflow** - For how-to questions
- **eBPF Slack** - For discussion
- **Mailing List** - For kernel-level issues

### Good Question Format

```
Environment:
- Kernel: 6.1.0
- Distribution: Ubuntu 22.04
- Tool: libbpf 1.0

What I'm trying to do:
[Brief description]

Code:
[Minimal example]

Error:
[Complete error message]

What I've tried:
[List of attempts]
```

---

!!! tip "Stay Updated"
    eBPF evolves rapidly. Follow the [BPF mailing list](https://lore.kernel.org/bpf/)
    and [eBPF.io](https://ebpf.io/) for the latest developments, new helpers,
    and expanded program types.
