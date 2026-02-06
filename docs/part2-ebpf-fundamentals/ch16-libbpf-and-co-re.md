# Chapter 16: libbpf and CO-RE

While BCC is great for prototyping, production eBPF tools typically use **libbpf** — a lightweight C library that loads precompiled eBPF programs. Combined with **CO-RE** (Compile Once, Run Everywhere), you can build tools that work across kernel versions without runtime compilation.

This chapter covers the libbpf approach, skeleton generation, and CO-RE concepts.

## Why libbpf?

| BCC Limitation | libbpf Solution |
|----------------|-----------------|
| Requires clang + LLVM on target | Precompiled .o files |
| Needs kernel headers at runtime | CO-RE reads BTF from kernel |
| Higher memory footprint | Minimal dependencies |
| Slower startup (compile time) | Fast loading |
| Harder to distribute | Single binary deployment |

## The libbpf Workflow

```
┌──────────────────────┐
│    program.bpf.c     │  ← Your eBPF C code
└──────────┬───────────┘
           │ clang -O2 -g -target bpf
           ▼
┌──────────────────────┐
│    program.bpf.o     │  ← Compiled eBPF object
└──────────┬───────────┘
           │ bpftool gen skeleton
           ▼
┌──────────────────────┐
│   program.skel.h     │  ← Auto-generated header
└──────────────────────┘

┌──────────────────────┐
│    program.c         │  ← Your userspace loader
│  #include "program.skel.h"
└──────────┬───────────┘
           │ cc + libbpf
           ▼
┌──────────────────────┐
│    program           │  ← Final binary (single file)
└──────────────────────┘
```

## Project Structure

A typical libbpf project:

```
my_tool/
├── Makefile
├── src/
│   ├── my_tool.bpf.c      # eBPF kernel code
│   └── my_tool.c          # Userspace loader
└── vmlinux/
    └── vmlinux.h          # Kernel types (from BTF)
```

## Writing the eBPF Program

### The Kernel Side: my_tool.bpf.c

```c
// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

// Define a map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u64);
} counter SEC(".maps");

// License is required
char LICENSE[] SEC("license") = "GPL";

// A kprobe handler
SEC("kprobe/sys_clone")
int BPF_KPROBE(trace_clone) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *count, init_val = 1;

    count = bpf_map_lookup_elem(&counter, &pid);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        bpf_map_update_elem(&counter, &pid, &init_val, BPF_ANY);
    }

    return 0;
}
```

### Key Differences from BCC

| BCC | libbpf |
|-----|--------|
| `BPF_HASH(name, key, val)` | BTF-defined struct with `.maps` section |
| `name.lookup(&key)` | `bpf_map_lookup_elem(&name, &key)` |
| `name.update(&key, &val)` | `bpf_map_update_elem(&name, &key, &val, flags)` |
| Function name is free | `SEC("...")` declares program type |
| Python handles attachment | Skeleton provides typed API |

## Map Definitions

libbpf uses BTF-defined maps:

```c
// Hash map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct event_t);
} events SEC(".maps");

// Per-CPU array
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 256);
    __type(key, u32);
    __type(value, u64);
} stats SEC(".maps");

// Ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // 256 KB
} rb SEC(".maps");
```

## SEC Macros for Program Types

```c
// Kprobe
SEC("kprobe/do_sys_open")
int BPF_KPROBE(my_kprobe, int dfd, const char *filename) { ... }

// Kretprobe
SEC("kretprobe/do_sys_open")
int BPF_KRETPROBE(my_kretprobe, long ret) { ... }

// Tracepoint
SEC("tp/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx) { ... }

// Raw tracepoint
SEC("raw_tp/sched_process_exec")
int handle_exec(struct bpf_raw_tracepoint_args *ctx) { ... }

// XDP
SEC("xdp")
int xdp_prog(struct xdp_md *ctx) { ... }

// TC (traffic control)
SEC("tc")
int tc_prog(struct __sk_buff *skb) { ... }

// Socket filter
SEC("socket")
int socket_filter(struct __sk_buff *skb) { ... }
```

## What is CO-RE?

**CO-RE** (Compile Once, Run Everywhere) lets eBPF programs work across different kernel versions without recompilation.

The problem: Kernel structs change between versions. Field offsets shift.

```c
// Kernel 5.8: sk_common at offset 0
// Kernel 5.15: sk_common at offset 8 (hypothetical)
struct sock *sk;
u32 family = sk->__sk_common.skc_family;  // Wrong offset?
```

The solution: **BTF** (BPF Type Format) describes kernel types. libbpf reads BTF at load time and adjusts offsets.

### Using CO-RE Helpers

```c
#include <bpf/bpf_core_read.h>

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(trace_connect, struct sock *sk) {
    // CO-RE aware read
    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

    // Works regardless of struct layout changes
    return 0;
}
```

### CO-RE Macros

| Macro | Purpose |
|-------|---------|
| `BPF_CORE_READ(src, field)` | Read field with relocation |
| `BPF_CORE_READ_INTO(&dst, src, field)` | Read into variable |
| `BPF_CORE_READ_STR_INTO(&dst, src, field)` | Read string |
| `bpf_core_field_exists(field)` | Check if field exists |
| `bpf_core_field_size(field)` | Get field size |
| `bpf_core_enum_value_exists(enum_val)` | Check enum value exists |

### Handling Kernel Differences

```c
SEC("kprobe/some_function")
int BPF_KPROBE(my_probe, struct task_struct *task) {
    u32 pid;

    // Check if field exists (handle kernel version differences)
    if (bpf_core_field_exists(task->thread_pid)) {
        // New kernel
        struct pid *pid_struct = BPF_CORE_READ(task, thread_pid);
        pid = BPF_CORE_READ(pid_struct, numbers[0].nr);
    } else {
        // Old kernel
        pid = BPF_CORE_READ(task, pid);
    }

    return 0;
}
```

## Generating vmlinux.h

vmlinux.h contains all kernel type definitions. Generate it from your kernel's BTF:

```bash
# From running kernel
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Or from vmlinux ELF (with debug info)
bpftool btf dump file /usr/lib/debug/boot/vmlinux-$(uname -r) format c > vmlinux.h
```

!!! note "vmlinux.h Size"
    vmlinux.h is large (~5MB) but you only include it once. Your compiled .bpf.o only includes types you actually use.

## Writing the Userspace Loader

### The Skeleton

After compiling `my_tool.bpf.c` to `my_tool.bpf.o`, generate a skeleton:

```bash
bpftool gen skeleton my_tool.bpf.o > my_tool.skel.h
```

The skeleton provides:

- `my_tool_bpf__open()` — Allocate eBPF object
- `my_tool_bpf__load()` — Load into kernel
- `my_tool_bpf__attach()` — Attach all programs
- `my_tool_bpf__destroy()` — Cleanup
- `skel->maps.counter` — Access to maps
- `skel->progs.trace_clone` — Access to programs

### Loader Code: my_tool.c

```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "my_tool.skel.h"

static volatile bool running = true;

static void sig_handler(int sig) {
    running = false;
}

int main(int argc, char **argv) {
    struct my_tool_bpf *skel;
    int err;

    /* Set up signal handler */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Open BPF application */
    skel = my_tool_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Optional: modify settings before load */
    // bpf_map__set_max_entries(skel->maps.counter, 2048);

    /* Load & verify BPF programs */
    err = my_tool_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    /* Attach handlers */
    err = my_tool_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    printf("Tracing... Ctrl+C to exit\n");

    /* Main loop */
    while (running) {
        sleep(1);
        /* Could poll maps here */
    }

cleanup:
    my_tool_bpf__destroy(skel);
    return err < 0 ? 1 : 0;
}
```

### Reading Maps from Userspace

```c
#include <bpf/bpf.h>

// Get map file descriptor from skeleton
int map_fd = bpf_map__fd(skel->maps.counter);

// Lookup
u32 key = 1234;
u64 value;
if (bpf_map_lookup_elem(map_fd, &key, &value) == 0) {
    printf("PID %u: count = %lu\n", key, value);
}

// Iterate all entries
u32 prev_key, curr_key;
while (bpf_map_get_next_key(map_fd, &prev_key, &curr_key) == 0) {
    bpf_map_lookup_elem(map_fd, &curr_key, &value);
    printf("PID %u: %lu\n", curr_key, value);
    prev_key = curr_key;
}

// Delete
bpf_map_delete_elem(map_fd, &key);
```

### Using Ring Buffers

```c
// In BPF code
struct event {
    u32 pid;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("kprobe/sys_clone")
int trace_clone(void *ctx) {
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

```c
// In userspace
static int handle_event(void *ctx, void *data, size_t len) {
    struct event *e = data;
    printf("PID %d: %s\n", e->pid, e->comm);
    return 0;
}

int main() {
    struct ring_buffer *rb;
    // ... open and load skeleton ...

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    while (running) {
        ring_buffer__poll(rb, 100 /* timeout ms */);
    }

    ring_buffer__free(rb);
}
```

## Building with Makefile

```makefile
# Makefile for libbpf project

CLANG ?= clang
CC ?= gcc
BPFTOOL ?= bpftool

ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

CFLAGS := -g -O2 -Wall
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)

LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf)
LIBBPF_LDFLAGS := $(shell pkg-config --libs libbpf)

.PHONY: all clean

all: my_tool

# Compile BPF code
%.bpf.o: src/%.bpf.c vmlinux/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Generate skeleton
%.skel.h: %.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# Compile userspace
my_tool: src/my_tool.c my_tool.skel.h
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) $< -o $@ $(LIBBPF_LDFLAGS) -lelf -lz

clean:
	rm -f *.bpf.o *.skel.h my_tool
```

## Complete Example

### exec_tracer.bpf.c

```c
// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct event {
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[16];
    char filename[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx) {
    struct event *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    task = (struct task_struct *)bpf_get_current_task();

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename),
                            (void *)ctx->__data + ctx->filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

### exec_tracer.c

```c
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "exec_tracer.skel.h"

struct event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    char comm[16];
    char filename[256];
};

static volatile bool running = true;

static void sig_handler(int sig) { running = false; }

static int handle_event(void *ctx, void *data, size_t len) {
    struct event *e = data;
    printf("%-8d %-8d %-8d %-16s %s\n",
           e->pid, e->ppid, e->uid, e->comm, e->filename);
    return 0;
}

int main() {
    struct exec_tracer_bpf *skel;
    struct ring_buffer *rb;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = exec_tracer_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load BPF program\n");
        return 1;
    }

    if (exec_tracer_bpf__attach(skel)) {
        fprintf(stderr, "Failed to attach\n");
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("%-8s %-8s %-8s %-16s %s\n", "PID", "PPID", "UID", "COMM", "FILENAME");

    while (running) {
        ring_buffer__poll(rb, 100);
    }

    ring_buffer__free(rb);
cleanup:
    exec_tracer_bpf__destroy(skel);
    return 0;
}
```

## Exercises

1. **Convert BCC to libbpf**: Take your favorite BCC program and rewrite it using libbpf with a skeleton.

2. **CO-RE field access**: Write a program that reads process info using `BPF_CORE_READ` from `task_struct`. Include the process name, PID, and parent PID.

3. **Map iteration**: Create a hash map that counts events per PID. In userspace, periodically iterate and print the top 10 entries.

4. **Ring buffer consumer**: Build a program that sends structured events through a ring buffer and processes them in userspace.

5. **XDP with libbpf**: Write an XDP program using libbpf that counts packets per protocol (TCP, UDP, ICMP, other).

6. **Conditional compilation**: Use `bpf_core_field_exists()` to handle a struct that differs between kernel 5.10 and 5.15.
