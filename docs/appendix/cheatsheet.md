# eBPF Cheatsheet

Quick reference for common eBPF patterns, BPF helpers, map types, and program types.

## Program Types

| Type | SEC() Name | Attach Point | Use Case |
|------|------------|--------------|----------|
| Kprobe | `kprobe/func` | Kernel function entry | Function tracing |
| Kretprobe | `kretprobe/func` | Kernel function return | Return value tracing |
| Tracepoint | `tracepoint/cat/name` | Stable trace events | Syscalls, scheduler |
| XDP | `xdp` | Network driver (ingress) | DDoS, load balancing |
| TC | `tc/ingress`, `tc/egress` | Traffic control | Packet filtering/modification |
| Socket Filter | `socket` | Socket | Packet filtering |
| Cgroup SKB | `cgroup_skb/ingress` | Cgroup | Container networking |
| Cgroup Sock | `cgroup/sock` | Socket creation | Socket policy |
| Sock Ops | `sockops` | TCP events | Connection tracking |
| LSM | `lsm/hook_name` | Security hooks | Access control |

## Common BPF Helpers

### Process Info

```c
// Get current PID and TID
u64 pid_tgid = bpf_get_current_pid_tgid();
u32 pid = pid_tgid >> 32;
u32 tid = pid_tgid & 0xFFFFFFFF;

// Get UID and GID
u64 uid_gid = bpf_get_current_uid_gid();
u32 uid = uid_gid & 0xFFFFFFFF;
u32 gid = uid_gid >> 32;

// Get command name
char comm[16];
bpf_get_current_comm(&comm, sizeof(comm));

// Get task struct
struct task_struct *task = (struct task_struct *)bpf_get_current_task();
```

### Memory Access

```c
// Read from kernel memory
bpf_probe_read_kernel(&dst, size, src);

// Read from user memory
bpf_probe_read_user(&dst, size, user_ptr);

// Read string from user memory
bpf_probe_read_user_str(&dst, size, user_ptr);

// CO-RE read
u32 pid = BPF_CORE_READ(task, pid);
```

### Time

```c
// Nanoseconds since boot
u64 ts = bpf_ktime_get_ns();

// Boot time in nanoseconds
u64 boot_ts = bpf_ktime_get_boot_ns();
```

### Map Operations

```c
// Lookup
void *val = bpf_map_lookup_elem(&map, &key);

// Update
bpf_map_update_elem(&map, &key, &val, BPF_ANY);  // Create or update
bpf_map_update_elem(&map, &key, &val, BPF_NOEXIST);  // Create only
bpf_map_update_elem(&map, &key, &val, BPF_EXIST);  // Update only

// Delete
bpf_map_delete_elem(&map, &key);

// Lookup and delete (atomic)
bpf_map_lookup_and_delete_elem(&map, &key, &val);
```

### Output

```c
// Ring buffer (preferred)
struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
if (e) {
    // Fill event
    bpf_ringbuf_submit(e, 0);
}

// Perf buffer
bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));

// Debug print
bpf_printk("debug: pid=%d\n", pid);
```

## Map Types

| Type | Description | Max Entries |
|------|-------------|-------------|
| `BPF_MAP_TYPE_HASH` | Generic hash table | Configurable |
| `BPF_MAP_TYPE_ARRAY` | Array with integer keys | Fixed |
| `BPF_MAP_TYPE_PERCPU_HASH` | Per-CPU hash (no locks) | Configurable |
| `BPF_MAP_TYPE_PERCPU_ARRAY` | Per-CPU array | Fixed |
| `BPF_MAP_TYPE_LRU_HASH` | LRU eviction hash | Configurable |
| `BPF_MAP_TYPE_RINGBUF` | Ring buffer (events) | Size in bytes |
| `BPF_MAP_TYPE_PERF_EVENT_ARRAY` | Perf events | # CPUs |
| `BPF_MAP_TYPE_STACK_TRACE` | Stack traces | Configurable |
| `BPF_MAP_TYPE_DEVMAP` | Device redirect | # devices |
| `BPF_MAP_TYPE_CPUMAP` | CPU redirect | # CPUs |

### Map Definition (libbpf)

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} my_map SEC(".maps");
```

### Map Definition (BCC)

```c
BPF_HASH(my_hash, u32, u64);
BPF_ARRAY(my_array, u64, 256);
BPF_PERCPU_ARRAY(my_percpu, u64, 256);
BPF_RINGBUF_OUTPUT(events, 1 << 20);
```

## XDP Return Values

| Value | Action |
|-------|--------|
| `XDP_DROP` | Drop packet |
| `XDP_PASS` | Continue to stack |
| `XDP_TX` | Bounce back out same interface |
| `XDP_REDIRECT` | Redirect to another interface/CPU |
| `XDP_ABORTED` | Error, drop with trace |

## TC Return Values

| Value | Action |
|-------|--------|
| `TC_ACT_OK` | Continue processing |
| `TC_ACT_SHOT` | Drop packet |
| `TC_ACT_REDIRECT` | Redirect packet |
| `TC_ACT_STOLEN` | Packet consumed |
| `TC_ACT_UNSPEC` | Use default action |

## Packet Parsing Template

```c
SEC("xdp")
int parse_packet(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // IP
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Transport (accounting for IP options)
    void *transport = (void *)ip + (ip->ihl * 4);

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = transport;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        // Use tcp->source, tcp->dest, etc.
    }

    return XDP_PASS;
}
```

## Checksum Update

```c
// Incremental checksum update
static __always_inline void update_csum(__u16 *csum, __u16 old, __u16 new) {
    __u32 sum = ~(*csum) & 0xFFFF;
    sum += (~old & 0xFFFF) + new;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += sum >> 16;
    *csum = ~sum;
}

// Using helper (preferred)
bpf_l4_csum_replace(skb, offset, old_val, new_val, flags);
bpf_l3_csum_replace(skb, offset, old_val, new_val, size);
```

## Attachment Commands

### XDP

```bash
# Attach
ip link set dev eth0 xdp obj prog.o sec xdp

# Detach
ip link set dev eth0 xdp off

# Query
ip link show eth0
bpftool net show dev eth0
```

### TC

```bash
# Create qdisc
tc qdisc add dev eth0 clsact

# Attach ingress
tc filter add dev eth0 ingress bpf da obj prog.o sec tc/ingress

# Attach egress
tc filter add dev eth0 egress bpf da obj prog.o sec tc/egress

# Remove
tc qdisc del dev eth0 clsact
```

### Cgroup

```bash
# Attach
bpftool prog attach pinned /sys/fs/bpf/prog cgroup /sys/fs/cgroup sock_ops

# Detach
bpftool prog detach pinned /sys/fs/bpf/prog cgroup /sys/fs/cgroup sock_ops
```

## bpftool Commands

```bash
# List programs
bpftool prog list

# List maps
bpftool map list

# Dump map contents
bpftool map dump id <map_id>

# Show program bytecode
bpftool prog dump xlated id <prog_id>

# Generate skeleton
bpftool gen skeleton prog.bpf.o > prog.skel.h

# Get BTF info
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

## Verifier Limits

| Limit | Value | Notes |
|-------|-------|-------|
| Instructions | 1M (privileged) | 4096 for unprivileged |
| Stack size | 512 bytes | Use maps for larger data |
| Function calls | 8 nested | Tail calls don't count |
| Map lookups | ~32 per path | Depends on complexity |

## Common Verifier Errors

| Error | Solution |
|-------|----------|
| "invalid mem access" | Add bounds check before access |
| "unbounded loop" | Use `#pragma unroll` or bounded loop |
| "stack too deep" | Reduce local variables, use maps |
| "R0 invalid mem access" | Check map lookup return for NULL |
| "cannot pass map_value" | Use helper parameters correctly |

## Byte Order

```c
// Host to network (big endian)
__be16 port_be = bpf_htons(port);
__be32 ip_be = bpf_htonl(ip);

// Network to host
u16 port = bpf_ntohs(port_be);
u32 ip = bpf_ntohl(ip_be);
```

## Debug Techniques

```bash
# View debug output
sudo cat /sys/kernel/debug/tracing/trace_pipe

# Check verifier output
bpftool prog load prog.o /sys/fs/bpf/prog verbose

# Dump program stats
bpftool prog show id <id> --json | jq .run_cnt
```
