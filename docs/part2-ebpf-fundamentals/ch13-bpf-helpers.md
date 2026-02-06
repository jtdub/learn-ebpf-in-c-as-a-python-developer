# Chapter 13: BPF Helpers

BPF helpers are kernel-provided functions that eBPF programs can call. They're your standard library — the only way to interact with the kernel, access data structures, get timestamps, read memory, and perform other operations that pure eBPF bytecode cannot do.

Without helpers, eBPF programs would be limited to basic computation on their context struct. Helpers unlock the real power: reading kernel memory, updating maps, getting process information, modifying packets, and more.

## How Helpers Work

eBPF programs cannot call arbitrary kernel functions — that would be a security nightmare. Instead, the kernel exposes a curated set of helper functions, each identified by a number. The verifier checks that your program only calls helpers that are allowed for its program type.

```c
// Helpers look like regular function calls in C
__u64 ts = bpf_ktime_get_ns();
__u32 pid = bpf_get_current_pid_tgid() >> 32;
bpf_printk("PID %d at time %llu\n", pid, ts);
```

Behind the scenes, these compile to special BPF call instructions:

```
call bpf_ktime_get_ns  ; Helper #5
call bpf_get_current_pid_tgid  ; Helper #14
```

## Helper Categories

Helpers fall into several categories:

| Category | Purpose | Example Helpers |
|----------|---------|-----------------|
| **Map operations** | Access BPF maps | `bpf_map_lookup_elem`, `bpf_map_update_elem` |
| **Time** | Get timestamps | `bpf_ktime_get_ns`, `bpf_ktime_get_boot_ns` |
| **Process info** | Current task context | `bpf_get_current_pid_tgid`, `bpf_get_current_comm` |
| **Memory access** | Safe memory reads | `bpf_probe_read_kernel`, `bpf_probe_read_user` |
| **Debugging** | Print debug output | `bpf_printk`, `bpf_trace_printk` |
| **Packet access** | Packet manipulation | `bpf_skb_load_bytes`, `bpf_skb_store_bytes` |
| **Checksums** | Calculate/update checksums | `bpf_csum_diff`, `bpf_l3_csum_replace` |
| **Redirect** | Redirect packets/messages | `bpf_redirect`, `bpf_msg_redirect_map` |
| **Random** | Generate random numbers | `bpf_get_prandom_u32` |
| **Socket** | Socket operations | `bpf_sk_lookup_tcp`, `bpf_sk_release` |

## Essential Helpers

### Map Operations

```c
// Lookup — returns pointer or NULL
void *bpf_map_lookup_elem(struct bpf_map *map, const void *key);

// Update — insert or update
int bpf_map_update_elem(struct bpf_map *map, const void *key,
                        const void *value, __u64 flags);

// Delete
int bpf_map_delete_elem(struct bpf_map *map, const void *key);
```

Example:

```c
__u32 key = 0;
__u64 *val = bpf_map_lookup_elem(&my_map, &key);
if (val) {
    (*val)++;
}

// Or update with new value
__u64 new_val = 100;
bpf_map_update_elem(&my_map, &key, &new_val, BPF_ANY);
```

### Time Functions

```c
// Nanoseconds since boot (monotonic)
__u64 bpf_ktime_get_ns(void);

// Nanoseconds since boot including suspend time
__u64 bpf_ktime_get_boot_ns(void);

// Nanoseconds since boot (coarse, faster)
__u64 bpf_ktime_get_coarse_ns(void);
```

Example:

```c
__u64 start = bpf_ktime_get_ns();
// ... do work ...
__u64 duration = bpf_ktime_get_ns() - start;
```

### Process Information

```c
// Get current PID and TGID (packed into 64 bits)
__u64 bpf_get_current_pid_tgid(void);
// Upper 32 bits = PID (actually TGID in kernel terms)
// Lower 32 bits = TID (actually PID in kernel terms)

// Get current UID and GID
__u64 bpf_get_current_uid_gid(void);
// Upper 32 bits = GID
// Lower 32 bits = UID

// Get current task's command name
int bpf_get_current_comm(void *buf, __u32 size);

// Get current cgroup ID
__u64 bpf_get_current_cgroup_id(void);
```

Example:

```c
__u64 pid_tgid = bpf_get_current_pid_tgid();
__u32 pid = pid_tgid >> 32;       // What userspace calls "PID"
__u32 tid = pid_tgid & 0xFFFFFFFF; // Thread ID

char comm[16];
bpf_get_current_comm(&comm, sizeof(comm));

bpf_printk("PID %d (%s)\n", pid, comm);
```

!!! note "PID vs TGID"
    Linux kernel terminology differs from userspace:

    - Kernel "PID" = userspace thread ID
    - Kernel "TGID" = userspace process ID

    `bpf_get_current_pid_tgid()` returns TGID in the upper bits (what you usually want) and PID in the lower bits.

### Memory Access

eBPF programs cannot dereference arbitrary pointers — the verifier would reject it. Use these helpers for safe memory access:

```c
// Read from kernel memory (e.g., kernel data structures)
int bpf_probe_read_kernel(void *dst, __u32 size, const void *src);

// Read from user memory (e.g., syscall arguments)
int bpf_probe_read_user(void *dst, __u32 size, const void *src);

// Read null-terminated string from kernel memory
int bpf_probe_read_kernel_str(void *dst, __u32 size, const void *src);

// Read null-terminated string from user memory
int bpf_probe_read_user_str(void *dst, __u32 size, const void *src);

// Copy from one BPF stack variable to another (verifier-friendly)
int bpf_probe_read(void *dst, __u32 size, const void *src);
```

Example — reading from a kernel struct:

```c
SEC("kprobe/tcp_connect")
int trace_connect(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

    // Can't dereference sk directly — use helper
    __u16 dport;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);

    bpf_printk("Connecting to port %d\n", bpf_ntohs(dport));
    return 0;
}
```

### Debugging: bpf_printk

The simplest debugging tool — prints to the kernel trace pipe:

```c
// Up to 3 format arguments
bpf_printk("value = %d, ptr = %p\n", value, ptr);
```

Read output:

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

!!! warning "bpf_printk Limitations"
    - Maximum 3 format arguments
    - Limited format specifiers (`%d`, `%u`, `%x`, `%p`, `%s`)
    - Performance overhead — don't use in production hot paths
    - For production, use ring buffers to send events to userspace

### Random Numbers

```c
__u32 bpf_get_prandom_u32(void);
```

Example — random sampling:

```c
// Sample 1% of events
if (bpf_get_prandom_u32() % 100 == 0) {
    // Process this event
}
```

## Packet Helpers (XDP/TC)

### Direct Packet Access

For XDP and TC, you access packet data directly through `ctx->data`:

```c
void *data = (void *)(long)ctx->data;
void *data_end = (void *)(long)ctx->data_end;

struct ethhdr *eth = data;
if ((void *)(eth + 1) > data_end)
    return XDP_DROP;
```

### Packet Modification Helpers (TC)

TC programs use helpers for packet modification:

```c
// Load bytes from packet
int bpf_skb_load_bytes(const struct __sk_buff *skb, __u32 offset,
                       void *to, __u32 len);

// Store bytes to packet
int bpf_skb_store_bytes(struct __sk_buff *skb, __u32 offset,
                        const void *from, __u32 len, __u64 flags);

// Adjust room in packet (add/remove headers)
int bpf_skb_adjust_room(struct __sk_buff *skb, __s32 len_diff,
                        __u32 mode, __u64 flags);

// Change packet type (e.g., for redirecting)
int bpf_skb_change_type(struct __sk_buff *skb, __u32 type);
```

### Checksum Helpers

When you modify packet headers, you must update checksums:

```c
// Update L3 (IP) checksum after modifying header
int bpf_l3_csum_replace(struct __sk_buff *skb, __u32 offset,
                        __u64 from, __u64 to, __u64 size);

// Update L4 (TCP/UDP) checksum after modifying header
int bpf_l4_csum_replace(struct __sk_buff *skb, __u32 offset,
                        __u64 from, __u64 to, __u64 flags);

// Calculate checksum difference
__s64 bpf_csum_diff(__be32 *from, __u32 from_size,
                    __be32 *to, __u32 to_size, __wsum seed);
```

Example — changing destination IP:

```c
// Update IP header
__u32 old_ip = ip->daddr;
__u32 new_ip = NEW_DEST_IP;
ip->daddr = new_ip;

// Fix IP checksum
bpf_l3_csum_replace(skb, IP_CSUM_OFFSET, old_ip, new_ip, sizeof(new_ip));

// Fix TCP checksum (TCP checksum covers IP addresses)
bpf_l4_csum_replace(skb, TCP_CSUM_OFFSET, old_ip, new_ip,
                    BPF_F_PSEUDO_HDR | sizeof(new_ip));
```

### Redirect Helpers

```c
// XDP: redirect to another interface or CPU
int bpf_redirect(__u32 ifindex, __u64 flags);
int bpf_redirect_map(struct bpf_map *map, __u32 key, __u64 flags);

// TC: redirect packet
int bpf_redirect(__u32 ifindex, __u64 flags);
int bpf_clone_redirect(struct __sk_buff *skb, __u32 ifindex, __u64 flags);
```

## Ring Buffer Helpers

```c
// Reserve space in ring buffer
void *bpf_ringbuf_reserve(struct bpf_map *ringbuf, __u64 size, __u64 flags);

// Submit reserved event
void bpf_ringbuf_submit(void *data, __u64 flags);

// Discard reserved event (e.g., on error)
void bpf_ringbuf_discard(void *data, __u64 flags);

// Simpler: output data directly (less efficient)
int bpf_ringbuf_output(struct bpf_map *ringbuf, void *data,
                       __u64 size, __u64 flags);
```

Pattern:

```c
struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
if (!e)
    return 0;

e->pid = bpf_get_current_pid_tgid() >> 32;
// Fill other fields...

bpf_ringbuf_submit(e, 0);
```

## Socket Helpers

For programs that work with sockets:

```c
// Look up a TCP socket
struct bpf_sock *bpf_sk_lookup_tcp(void *ctx, struct bpf_sock_tuple *tuple,
                                    __u32 tuple_size, __u64 netns, __u64 flags);

// Look up a UDP socket
struct bpf_sock *bpf_sk_lookup_udp(void *ctx, struct bpf_sock_tuple *tuple,
                                    __u32 tuple_size, __u64 netns, __u64 flags);

// Release socket reference
void bpf_sk_release(struct bpf_sock *sock);
```

## Helper Availability by Program Type

Not all helpers are available to all program types. The kernel restricts helpers based on what makes sense:

| Helper | XDP | TC | Kprobe | Tracepoint | Cgroup |
|--------|-----|----|---------|-----------| -------|
| `bpf_map_*` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `bpf_ktime_get_ns` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `bpf_get_current_pid_tgid` | ✗ | ✗ | ✓ | ✓ | ✓ |
| `bpf_probe_read_kernel` | ✗ | ✗ | ✓ | ✓ | ✗ |
| `bpf_skb_load_bytes` | ✗ | ✓ | ✗ | ✗ | ✗ |
| `bpf_redirect` | ✓ | ✓ | ✗ | ✗ | ✗ |
| `bpf_printk` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `bpf_sk_lookup_tcp` | ✓ | ✓ | ✗ | ✗ | ✓ |

Check availability:

```bash
# List all helpers
bpftool feature probe

# See which helpers a program type supports
bpftool feature probe | grep -A 100 "program_type xdp"
```

## Common Patterns

### Safe Struct Field Reading

```c
// Reading nested struct fields from kernel memory
struct task_struct *task;
bpf_probe_read_kernel(&task, sizeof(task), &current);

char comm[16];
bpf_probe_read_kernel_str(&comm, sizeof(comm), task->comm);
```

### Timestamped Events

```c
struct event {
    __u64 timestamp;
    __u32 pid;
    // ...
};

struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
if (!e) return 0;

e->timestamp = bpf_ktime_get_ns();
e->pid = bpf_get_current_pid_tgid() >> 32;
// ...
bpf_ringbuf_submit(e, 0);
```

### Rate Limiting with Random Sampling

```c
// Sample approximately 1 in 1000 events
if ((bpf_get_prandom_u32() & 0x3FF) == 0) {
    // Process this event
}
```

## Exercises

1. **Helper exploration**: Use `bpftool feature probe` to list all available helpers. Identify 5 helpers you haven't seen before and look up what they do.

2. **Timing measurement**: Write a kprobe that measures how long a kernel function takes, using `bpf_ktime_get_ns()` in the kprobe and kretprobe.

3. **Process context**: Write a program that logs PID, TID, UID, GID, and comm for every execve. Verify the values match `ps` output.

4. **Safe memory read**: Write a kprobe for `tcp_sendmsg` that reads the socket's destination port using `bpf_probe_read_kernel()`.

5. **Helper error handling**: Most helpers return 0 on success, negative on error. Write a program that checks helper return values and handles errors.

6. **Packet modification**: Write a TC program that modifies a packet header and correctly updates the checksum using `bpf_l3_csum_replace()`.
