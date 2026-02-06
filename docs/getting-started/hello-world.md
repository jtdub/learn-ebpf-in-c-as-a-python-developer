# Hello World — Your First eBPF Program

Let's write a minimal eBPF program to prove your environment works, then break down every line so you understand what's happening. We'll use BCC first (since it lets you write the loader in Python), then show the pure C equivalent.

## The BCC Version (Python + C)

Create a file called `hello.py`:

```python
from bcc import BPF

# The eBPF program is written in C, embedded as a string
program = r"""
int hello(void *ctx) {
    bpf_trace_printk("Hello, eBPF!\n");
    return 0;
}
"""

# Load the C code, compile it to BPF bytecode, and load it into the kernel
b = BPF(text=program)

# Attach the program to a kernel event — every time a syscall executes,
# our function runs inside the kernel
b.attach_kprobe(event="__x64_sys_execve", fn_name="hello")

# Read the output from the kernel's trace pipe
print("Tracing execve()... Hit Ctrl-C to stop.")
b.trace_print()
```

Run it:

```bash
sudo python3 hello.py
```

Open another terminal and run any command (like `ls` or `whoami`). You should see output like:

```
ls-12345   [001] ....  1234.567890: 0: Hello, eBPF!
```

Every time a process calls `execve()` (which happens whenever you run a command), your eBPF function fires inside the kernel and prints a message.

### What Just Happened?

Let's break down each piece:

| Line | What It Does |
|------|-------------|
| `from bcc import BPF` | Import the BCC library — Python bindings for loading eBPF programs |
| `program = r"""..."""` | A C program as a Python string. BCC compiles this to BPF bytecode behind the scenes |
| `int hello(void *ctx)` | A C function that takes a generic context pointer. This is the eBPF program entry point |
| `bpf_trace_printk(...)` | A BPF helper function that writes to the kernel trace pipe (`/sys/kernel/debug/tracing/trace_pipe`) |
| `return 0;` | eBPF programs must return an integer |
| `BPF(text=program)` | Compile the C code to BPF bytecode using clang, then load it into the kernel |
| `attach_kprobe(...)` | Hook the eBPF program to fire whenever `execve` is called |
| `trace_print()` | Read and print the kernel trace pipe output |

### Python Parallel

Think of it this way — in Python terms:

=== "Python Analogy"

    ```python
    import signal

    def hello(signum, frame):
        """This runs whenever the event fires"""
        print("Hello from signal handler!")

    # Attach our function to an event (SIGUSR1)
    signal.signal(signal.SIGUSR1, hello)

    # Wait for events
    signal.pause()
    ```

=== "eBPF Reality"

    ```python
    from bcc import BPF

    program = r"""
    int hello(void *ctx) {
        bpf_trace_printk("Hello, eBPF!\n");
        return 0;
    }
    """

    b = BPF(text=program)
    b.attach_kprobe(event="__x64_sys_execve", fn_name="hello")
    b.trace_print()
    ```

The concept is identical: register a function to fire on an event. The difference is that eBPF functions run **inside the kernel**, not in your process. They're triggered by kernel events (syscalls, network packets, scheduler decisions), not signals.

## The Pure C Version (libbpf)

Here's the same program without BCC — pure C on both sides. This is more verbose but is the production-standard approach.

### The eBPF Program (`hello.bpf.c`)

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("kprobe/__x64_sys_execve")
int hello(void *ctx) {
    bpf_printk("Hello, eBPF!");
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

### Compile It

```bash
clang -target bpf -O2 -g -c hello.bpf.c -o hello.bpf.o
```

### Load It with bpftool

```bash
# Load the program
sudo bpftool prog load hello.bpf.o /sys/fs/bpf/hello

# Attach it to the kprobe
sudo bpftool prog attach pinned /sys/fs/bpf/hello kprobe __x64_sys_execve

# Read trace output
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### What's Different?

| BCC Version | libbpf Version |
|-------------|---------------|
| C code as a Python string | C code in its own `.bpf.c` file |
| BCC compiles at runtime | You compile ahead of time with `clang` |
| Python loads and attaches | `bpftool` or a C loader program loads and attaches |
| Good for prototyping | Good for production |
| Requires clang + kernel headers on target | Portable via CO-RE (Compile Once, Run Everywhere) |

## Key Takeaways

1. **eBPF programs are small C functions** that run inside the Linux kernel
2. **They attach to events** — syscalls, network hooks, scheduler events, etc.
3. **They can't do arbitrary things** — the verifier restricts what's allowed (no unbounded loops, no arbitrary memory access)
4. **BCC lets you use Python** as the userspace component — great for learning
5. **libbpf is the production standard** — more setup, but portable and efficient

## What's Next

Before diving deeper into eBPF, you need to be comfortable reading and writing C. If you already know C, skip to [Part 2: eBPF Fundamentals](../part2-ebpf-fundamentals/index.md). Otherwise, start with [Part 1: C Fundamentals](../part1-c-fundamentals/index.md) — it's designed specifically for Python developers and moves fast.
