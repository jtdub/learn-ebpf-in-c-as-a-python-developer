# Chapter 9: Build Tools

You have written C code for eBPF. Now you need to compile it. This chapter covers the toolchain: `clang` for compilation, `bpftool` for inspection, and `make` for automation. By the end, you'll have a repeatable build process for your eBPF programs.

## The eBPF Compilation Pipeline

Regular C programs compile to native machine code for your CPU. eBPF programs compile to **BPF bytecode** — a platform-independent instruction set that the kernel's BPF virtual machine executes (or JIT-compiles to native code).

```
Source (.bpf.c)  →  clang -target bpf  →  BPF object (.bpf.o)  →  Loader  →  Kernel
```

The key tool is `clang` with `-target bpf`, which produces BPF bytecode in an ELF object file.

## Basic Compilation with clang

### Minimal Command

```bash
clang -target bpf -O2 -g -c my_program.bpf.c -o my_program.bpf.o
```

Let's break down each flag:

| Flag | Meaning |
|------|---------|
| `-target bpf` | Compile for the BPF virtual machine, not your CPU |
| `-O2` | Optimization level 2 (recommended for eBPF) |
| `-g` | Include debug information (needed for BTF) |
| `-c` | Compile only (produce object file, don't link) |
| `-o my_program.bpf.o` | Output filename |

### Adding Include Paths

You'll need to include kernel headers and libbpf headers:

```bash
clang -target bpf -O2 -g \
    -I/usr/include \
    -I/usr/src/linux-headers-$(uname -r)/include \
    -c my_program.bpf.c -o my_program.bpf.o
```

### Common Additional Flags

```bash
clang -target bpf -O2 -g \
    -D__TARGET_ARCH_x86 \          # Architecture definition
    -Wall \                         # Enable warnings
    -Werror \                       # Treat warnings as errors
    -c my_program.bpf.c -o my_program.bpf.o
```

## Understanding the Output: ELF Sections

The compiled `.bpf.o` file is an ELF object file with special sections. Use `llvm-objdump` to inspect it:

```bash
llvm-objdump -h my_program.bpf.o
```

Output:

```
Sections:
Idx Name              Size     VMA      Type
  0                   00000000 0000000000000000
  1 .text             00000000 0000000000000000 TEXT
  2 xdp               000000a8 0000000000000000 TEXT
  3 .maps             00000020 0000000000000000 DATA
  4 license           00000004 0000000000000000 DATA
  5 .BTF              00000258 0000000000000000
  6 .BTF.ext          00000098 0000000000000000
```

Key sections:

| Section | Content |
|---------|---------|
| `xdp`, `kprobe/*`, `tc`, etc. | Your eBPF program code (from `SEC()` macro) |
| `.maps` | BPF map definitions |
| `license` | License string (required for some helpers) |
| `.BTF` | BTF type information |
| `.BTF.ext` | BTF extension info (line numbers, etc.) |

## Viewing the BPF Bytecode

To see the actual BPF instructions:

```bash
llvm-objdump -d my_program.bpf.o
```

Output:

```
my_program.bpf.o:       file format elf64-bpf

Disassembly of section xdp:

0000000000000000 <my_xdp_program>:
       0:       79 12 00 00 00 00 00 00 r2 = *(u64 *)(r1 + 0x0)
       1:       79 11 08 00 00 00 00 00 r1 = *(u64 *)(r1 + 0x8)
       2:       bf 23 00 00 00 00 00 00 r3 = r2
       ...
```

This is rarely needed for normal development, but it's useful for understanding what the compiler generates and debugging verifier errors.

## BTF: BPF Type Format

BTF (BPF Type Format) is type information embedded in the object file. It enables:

- Better `bpftool` output (shows struct field names)
- CO-RE (Compile Once, Run Everywhere) — your program adapts to different kernel versions
- More informative verifier errors

BTF is generated automatically with `-g`. Verify it's present:

```bash
bpftool btf dump file my_program.bpf.o
```

## bpftool: Inspecting and Managing BPF

`bpftool` is the Swiss Army knife for eBPF. Use it to load programs, inspect maps, and debug.

### Listing Loaded Programs

```bash
sudo bpftool prog list
# or: sudo bpftool prog show
```

Output:

```
15: xdp  name my_xdp_program  tag a1b2c3d4e5f67890  gpl
        loaded_at 2026-02-06T14:30:00+0000  uid 0
        xlated 168B  jited 126B  memlock 4096B  map_ids 3,4
        btf_id 12
```

### Loading a Program

```bash
sudo bpftool prog load my_program.bpf.o /sys/fs/bpf/my_prog
```

This loads the program and pins it to the BPF filesystem. The program stays loaded until unpinned or the system reboots.

### Attaching to an Interface (XDP)

```bash
# Attach XDP program to eth0
sudo bpftool net attach xdp id 15 dev eth0

# Or attach by pinned path
sudo bpftool net attach xdp pinned /sys/fs/bpf/my_prog dev eth0

# Detach
sudo bpftool net detach xdp dev eth0
```

### Listing Maps

```bash
sudo bpftool map list
sudo bpftool map show id 3
```

### Dumping Map Contents

```bash
sudo bpftool map dump id 3
```

### Dumping Program Instructions

```bash
sudo bpftool prog dump xlated id 15
sudo bpftool prog dump jited id 15  # JIT-compiled native code
```

## Makefiles for eBPF Projects

Typing long `clang` commands is tedious and error-prone. Use a Makefile:

### Minimal Makefile

```makefile
# Compiler and flags
CLANG := clang
CFLAGS := -target bpf -O2 -g -Wall

# Source and output
SRC := my_program.bpf.c
OBJ := my_program.bpf.o

# Default target
all: $(OBJ)

# Compile BPF program
$(OBJ): $(SRC)
	$(CLANG) $(CFLAGS) -c $< -o $@

# Clean up
clean:
	rm -f $(OBJ)

.PHONY: all clean
```

Run with:

```bash
make        # Build
make clean  # Remove built files
```

### Full-Featured Makefile

Here's a more complete Makefile for a project with multiple programs:

```makefile
# Tools
CLANG := clang
LLC := llc
BPFTOOL := bpftool

# Flags
ARCH := $(shell uname -m | sed 's/x86_64/x86/')
CFLAGS := -target bpf \
          -D__TARGET_ARCH_$(ARCH) \
          -O2 -g -Wall -Werror \
          -I/usr/include \
          -I/usr/src/linux-headers-$(shell uname -r)/include

# Source files (all .bpf.c files in current directory)
BPF_SRCS := $(wildcard *.bpf.c)
BPF_OBJS := $(BPF_SRCS:.bpf.c=.bpf.o)

# Userspace loader sources (if any)
USER_SRCS := $(wildcard *_user.c)
USER_BINS := $(USER_SRCS:_user.c=)

# libbpf flags for userspace
LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf)
LIBBPF_LDFLAGS := $(shell pkg-config --libs libbpf) -lelf -lz

# Default target
all: $(BPF_OBJS) $(USER_BINS)

# Compile BPF programs
%.bpf.o: %.bpf.c
	$(CLANG) $(CFLAGS) -c $< -o $@

# Generate BPF skeleton (for libbpf userspace loaders)
%.skel.h: %.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# Compile userspace loaders
%: %_user.c %.skel.h
	$(CC) $(LIBBPF_CFLAGS) -o $@ $< $(LIBBPF_LDFLAGS)

# Clean up
clean:
	rm -f *.bpf.o *.skel.h $(USER_BINS)

# Show loaded programs (convenience target)
show:
	sudo $(BPFTOOL) prog list

.PHONY: all clean show
```

### Using the Makefile

```bash
# Build everything
make

# Build specific program
make my_program.bpf.o

# Clean and rebuild
make clean && make

# List loaded programs
make show
```

## The libbpf Skeleton Workflow

For production eBPF with libbpf, there's a recommended workflow that generates a "skeleton" header:

### Step 1: Write the BPF Program

```c
// my_prog.bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} my_map SEC(".maps");

SEC("xdp")
int my_xdp(struct xdp_md *ctx) {
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
```

### Step 2: Compile

```bash
clang -target bpf -O2 -g -c my_prog.bpf.c -o my_prog.bpf.o
```

### Step 3: Generate Skeleton

```bash
bpftool gen skeleton my_prog.bpf.o > my_prog.skel.h
```

This generates a header with functions to load and attach your program:

```c
// Generated my_prog.skel.h (simplified)
struct my_prog {
    struct bpf_object *obj;
    struct bpf_program *progs_my_xdp;
    struct bpf_map *maps_my_map;
};

struct my_prog *my_prog__open(void);
int my_prog__load(struct my_prog *skel);
int my_prog__attach(struct my_prog *skel);
void my_prog__destroy(struct my_prog *skel);
```

### Step 4: Write Userspace Loader

```c
// my_prog_user.c
#include <stdio.h>
#include <bpf/libbpf.h>
#include "my_prog.skel.h"

int main(int argc, char **argv) {
    struct my_prog *skel;

    // Open and load
    skel = my_prog__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load BPF program\n");
        return 1;
    }

    // Attach (you'd typically attach to an interface here)
    // For XDP, you'd use bpf_xdp_attach() or similar

    // Keep running...
    printf("BPF program loaded. Press Ctrl+C to exit.\n");
    while (1) {
        sleep(1);
    }

    my_prog__destroy(skel);
    return 0;
}
```

### Step 5: Compile Userspace

```bash
gcc -o my_prog my_prog_user.c -lbpf -lelf -lz
```

## Verifier Errors

When your BPF program fails to load, the verifier tells you why. Here's how to read the output:

```bash
sudo bpftool prog load bad_program.bpf.o /sys/fs/bpf/bad 2>&1
```

Example error:

```
libbpf: prog 'my_xdp': BPF program load failed: Permission denied
libbpf: prog 'my_xdp': -- BEGIN PROG LOAD LOG --
0: (79) r2 = *(u64 *)(r1 +0)
1: (79) r1 = *(u64 *)(r1 +8)
2: (bf) r3 = r2
3: (07) r3 += 14
4: (2d) if r3 > r1 goto pc+5
5: (71) r0 = *(u8 *)(r2 +12)
R2 invalid mem access 'scalar'
```

The error `R2 invalid mem access 'scalar'` means you're trying to read memory through a pointer that the verifier doesn't trust. Usually this means a missing bounds check.

## Common Compilation Problems

| Error | Cause | Fix |
|-------|-------|-----|
| `fatal error: 'linux/bpf.h' file not found` | Missing kernel headers | Install `linux-headers-$(uname -r)` |
| `unknown target 'bpf'` | Old clang version | Install clang 10+ |
| `BTF is missing` | Compiled without `-g` | Add `-g` to clang flags |
| Verifier rejection | Various safety issues | Read verifier output, add bounds checks |
| `relocation failed` | Using disallowed features | Check for global variables, function calls |

## Exercises

1. **Basic build**: Write a minimal XDP program that returns `XDP_PASS`. Compile it with `clang` and verify the sections with `llvm-objdump -h`.

2. **Makefile creation**: Create a Makefile that compiles your XDP program. Add a `clean` target and a `run` target that loads the program with `bpftool`.

3. **BTF inspection**: Compile a program with a struct definition. Use `bpftool btf dump file` to see the BTF type information. Compare output with and without `-g`.

4. **Skeleton workflow**: Follow the libbpf skeleton workflow: write a BPF program, compile it, generate a skeleton, and write a minimal userspace loader.

5. **Verifier debugging**: Write a program with a deliberate bug (missing bounds check). Attempt to load it and interpret the verifier error message. Then fix the bug.

6. **Multi-program project**: Create a project with two BPF programs (e.g., XDP and kprobe). Write a Makefile that builds both and generates skeletons for each.

7. **Build automation**: Add a `.PHONY` target to your Makefile called `test` that loads your program, runs a quick test, and unloads it.
