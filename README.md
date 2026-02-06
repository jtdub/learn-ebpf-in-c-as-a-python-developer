# Learn eBPF in C as a Python Developer

An in-depth guide for experienced Python developers who need to learn the fundamentals of the C programming language to work with eBPF.

## What is this?

This documentation takes you from Python expertise to writing production-ready eBPF programs in C. Rather than treating C as an entirely new language, it builds on your existing Python knowledge by showing direct comparisons and highlighting key differences.

### Topics Covered

- **Part 1: C Fundamentals** - Types, pointers, memory management, structs, and the preprocessor
- **Part 2: eBPF Fundamentals** - What eBPF is, program types, maps, the verifier, and toolchains (BCC & libbpf)
- **Part 3: Packet Interception** - XDP, TC, socket filters, packet parsing, and header manipulation
- **Part 4: Observability** - Kprobes, tracepoints, uprobes, and perf events
- **Part 5: Security** - eBPF security model, seccomp-BPF, and hardening
- **Projects** - 8 hands-on projects from syscall tracing to transparent proxy redirection
- **Appendix** - Cheatsheets, Python-to-C reference, and curated resources

## Getting Started

### Prerequisites

- Python 3.8+
- pip

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/learn-ebpf-in-c-as-a-python-developer.git
   cd learn-ebpf-in-c-as-a-python-developer
   ```

2. Create a virtual environment (recommended):
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Running the Documentation

Start the MkDocs development server:

```bash
mkdocs serve
```

Then open your browser to [http://127.0.0.1:8000](http://127.0.0.1:8000)

### Building Static Site

To build the static HTML site:

```bash
mkdocs build
```

The output will be in the `site/` directory.

## For eBPF Development

To actually run the eBPF examples in this guide, you'll need:

- **Linux kernel 5.8+** (5.15+ recommended for full feature support)
- **clang/LLVM** - For compiling BPF programs
- **libbpf-dev** - BPF loading library
- **bpftool** - BPF inspection tool
- **bcc-tools** - BCC Python framework (for earlier projects)

On Ubuntu/Debian:

```bash
sudo apt install clang llvm libbpf-dev linux-tools-$(uname -r) bpfcc-tools
```

See the [Development Environment](docs/getting-started/dev-environment.md) chapter for detailed setup instructions.

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

See [LICENSE](LICENSE) for details.
