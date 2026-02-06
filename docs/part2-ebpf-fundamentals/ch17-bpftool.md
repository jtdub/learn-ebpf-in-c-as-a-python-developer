# Chapter 17: bpftool

**bpftool** is the Swiss Army knife for eBPF — a command-line utility for inspecting, debugging, and managing eBPF programs and maps. Every eBPF developer should master it.

This chapter covers the essential bpftool commands you'll use daily.

## Installation

### Ubuntu/Debian

```bash
sudo apt-get install linux-tools-common linux-tools-$(uname -r)
```

### Fedora

```bash
sudo dnf install bpftool
```

### From Source

```bash
git clone https://github.com/libbpf/bpftool.git
cd bpftool/src
make
sudo make install
```

### Verify

```bash
bpftool version
```

## Listing Programs

See all loaded eBPF programs:

```bash
sudo bpftool prog list
# or
sudo bpftool prog show
```

Example output:

```
43: kprobe  name trace_clone  tag 9c9b2c7d8a5c8a7f  gpl
        loaded_at 2024-01-15T10:23:45+0000  uid 0
        xlated 128B  jited 96B  memlock 4096B  map_ids 12
        btf_id 54
        pids my_tool(1234)
```

| Field | Meaning |
|-------|---------|
| `43` | Program ID |
| `kprobe` | Program type |
| `name trace_clone` | Function name |
| `tag` | Hash of the instructions (changes if code changes) |
| `loaded_at` | When it was loaded |
| `xlated/jited` | Bytecode size / JIT-compiled size |
| `map_ids` | Associated maps |
| `btf_id` | BTF type information |
| `pids` | Process(es) holding the program |

### Filter by Type

```bash
sudo bpftool prog list type kprobe
sudo bpftool prog list type xdp
sudo bpftool prog list type tracepoint
```

## Inspecting Programs

### Show Program Details

```bash
sudo bpftool prog show id 43
sudo bpftool prog show name trace_clone
```

### Dump eBPF Bytecode

```bash
sudo bpftool prog dump xlated id 43
```

Output shows the translated (verified) instructions:

```
   0: (79) r6 = *(u64 *)(r1 +104)
   1: (bf) r1 = r6
   2: (85) call bpf_get_current_pid_tgid#14
   3: (77) r0 >>= 32
   ...
```

### Dump JIT Assembly

See the actual machine code:

```bash
sudo bpftool prog dump jited id 43
```

```
bpf_prog_9c9b2c7d8a5c8a7f_trace_clone:
   0:   nopl   0x0(%rax,%rax,1)
   5:   xchg   %ax,%ax
   7:   push   %rbp
   8:   mov    %rsp,%rbp
   ...
```

### Dump as JSON

Useful for scripting:

```bash
sudo bpftool prog show --json
sudo bpftool prog show id 43 --json --pretty
```

### Show Visual Graph

```bash
sudo bpftool prog dump xlated id 43 visual > prog.dot
dot -Tpng prog.dot -o prog.png
```

## Listing Maps

```bash
sudo bpftool map list
```

Output:

```
12: hash  name counter  flags 0x0
        key 4B  value 8B  max_entries 1024  memlock 98304B
        btf_id 54
        pids my_tool(1234)
```

| Field | Meaning |
|-------|---------|
| `12` | Map ID |
| `hash` | Map type |
| `name counter` | Map name |
| `key 4B` | Key size (4 bytes = u32) |
| `value 8B` | Value size (8 bytes = u64) |
| `max_entries` | Maximum capacity |

## Inspecting Maps

### Show All Entries

```bash
sudo bpftool map dump id 12
```

```
key: 01 00 00 00  value: 05 00 00 00 00 00 00 00
key: 02 00 00 00  value: 03 00 00 00 00 00 00 00
Found 2 elements
```

### Pretty Print (Requires BTF)

```bash
sudo bpftool map dump id 12 --pretty
```

```json
[{
        "key": 1,
        "value": 5
    },{
        "key": 2,
        "value": 3
    }
]
```

### Lookup Specific Key

```bash
# Key as hex bytes
sudo bpftool map lookup id 12 key hex 01 00 00 00

# Key as integer (in hex)
sudo bpftool map lookup id 12 key 0x01 0x00 0x00 0x00
```

### Update Entry

```bash
sudo bpftool map update id 12 key hex 01 00 00 00 value hex 0a 00 00 00 00 00 00 00
```

### Delete Entry

```bash
sudo bpftool map delete id 12 key hex 01 00 00 00
```

## Managing Programs

### Pin a Program

Pinning keeps a program loaded even after the loader exits:

```bash
sudo bpftool prog pin id 43 /sys/fs/bpf/my_prog
```

### Load from Pinned

```bash
# Other tools can reference it
sudo bpftool prog show pinned /sys/fs/bpf/my_prog
```

### Unpin

```bash
sudo rm /sys/fs/bpf/my_prog
```

### Pin a Map

```bash
sudo bpftool map pin id 12 /sys/fs/bpf/my_map
```

## Attaching Programs

### Attach XDP

```bash
# Attach
sudo bpftool net attach xdp id 43 dev eth0

# Or from pinned
sudo bpftool net attach xdp pinned /sys/fs/bpf/my_xdp dev eth0

# Detach
sudo bpftool net detach xdp dev eth0
```

### View Network Attachments

```bash
sudo bpftool net show
```

```
xdp:
eth0(3) driver id 43

tc:
eth0(3) clsact/ingress id 44
eth0(3) clsact/egress id 45
```

## BTF Operations

BTF (BPF Type Format) provides type information for better debugging.

### Check Kernel BTF

```bash
sudo bpftool btf show
```

```
1: name [vmlinux]  size 5842106B
2: name [...]  size 1234B
```

### Dump vmlinux.h

```bash
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

### Show BTF for a Program

```bash
sudo bpftool btf dump prog id 43
```

### Show BTF for a Map

```bash
sudo bpftool btf dump map id 12
```

## Generating Skeletons

Generate a C header for libbpf:

```bash
bpftool gen skeleton my_prog.bpf.o > my_prog.skel.h
bpftool gen skeleton my_prog.bpf.o name my_prog > my_prog.skel.h
```

## Useful One-Liners

### Count Loaded Programs by Type

```bash
sudo bpftool prog list --json | jq 'group_by(.type) | map({type: .[0].type, count: length})'
```

### Find Programs Using a Specific Map

```bash
sudo bpftool prog list --json | jq --arg map "12" '.[] | select(.map_ids[]? == ($map | tonumber))'
```

### Watch Map Updates

```bash
watch -n1 "sudo bpftool map dump id 12"
```

### Export All Maps to JSON

```bash
for id in $(sudo bpftool map list --json | jq '.[].id'); do
    echo "=== Map $id ==="
    sudo bpftool map dump id $id --json --pretty
done
```

### Find Programs by Name Pattern

```bash
sudo bpftool prog list --json | jq '.[] | select(.name | test("trace.*"))'
```

## Feature Detection

See what your kernel supports:

```bash
sudo bpftool feature
```

Shows:

- Kernel version
- Available program types
- Available map types
- Available helpers per program type

### Check Specific Feature

```bash
# Available helpers for XDP
sudo bpftool feature probe | grep -A100 "eBPF helpers supported for program type xdp"
```

## Cgroup Operations

### Attach to Cgroup

```bash
# Create cgroup for testing
sudo mkdir -p /sys/fs/cgroup/test

# Attach program
sudo bpftool cgroup attach /sys/fs/cgroup/test egress id 43

# List attachments
sudo bpftool cgroup show /sys/fs/cgroup/test

# Detach
sudo bpftool cgroup detach /sys/fs/cgroup/test egress id 43
```

## Debugging Tips

### Verbose Verifier Output

When loading fails, get detailed verifier logs:

```bash
sudo bpftool prog load my_prog.bpf.o /sys/fs/bpf/my_prog -d
```

### Check Program Stats

Enable stats:

```bash
sudo sysctl kernel.bpf_stats_enabled=1
```

Then view:

```bash
sudo bpftool prog show id 43
```

Now shows `run_cnt` and `run_time_ns`.

### Trace Execution

Use `bpf_trace_printk()` in your code, then:

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## Common Commands Reference

| Command | Purpose |
|---------|---------|
| `bpftool prog list` | List all programs |
| `bpftool prog show id N` | Show program details |
| `bpftool prog dump xlated id N` | Dump bytecode |
| `bpftool prog dump jited id N` | Dump JIT assembly |
| `bpftool map list` | List all maps |
| `bpftool map dump id N` | Show map contents |
| `bpftool map lookup id N key hex ...` | Lookup entry |
| `bpftool map update id N key hex ... value hex ...` | Update entry |
| `bpftool net show` | Show network attachments |
| `bpftool btf dump file /sys/kernel/btf/vmlinux format c` | Generate vmlinux.h |
| `bpftool gen skeleton X.bpf.o` | Generate skeleton |
| `bpftool feature` | Show kernel features |

## Exercises

1. **Program inspection**: Load a sample eBPF program (e.g., from BCC), find it with `bpftool prog list`, and dump its bytecode.

2. **Map manipulation**: Create a program with a hash map. Use bpftool to add, read, and delete entries.

3. **XDP management**: Write a simple XDP program, load it with bpftool, attach to an interface, verify with `bpftool net show`, then detach.

4. **BTF exploration**: Generate vmlinux.h for your kernel. Search it for a struct you're interested in (e.g., `task_struct`, `sk_buff`).

5. **Feature audit**: Use `bpftool feature` to check which helpers are available for kprobe programs on your system.

6. **Automation script**: Write a bash script that lists all eBPF programs, exports their map contents to JSON files, and summarizes memory usage.
