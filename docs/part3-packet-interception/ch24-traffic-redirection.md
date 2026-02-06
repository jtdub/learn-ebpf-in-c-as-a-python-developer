# Chapter 24: Traffic Redirection

Traffic redirection is one of eBPF's most powerful capabilities — sending packets to different interfaces, CPUs, or sockets without going through the full network stack. This chapter covers redirection techniques in XDP and TC.

## Redirection Overview

| Method | Program Type | Use Case |
|--------|--------------|----------|
| `bpf_redirect()` | XDP, TC | Send to another interface |
| `bpf_redirect_map()` | XDP, TC | Efficient multi-destination redirect |
| `bpf_redirect_peer()` | TC | Direct to veth peer (fast) |
| `bpf_clone_redirect()` | TC | Mirror traffic |
| `bpf_sk_redirect_map()` | SK_SKB | Socket-level redirect |

## XDP Redirect

### Direct Redirect

```c
SEC("xdp")
int xdp_redirect_simple(struct xdp_md *ctx) {
    // Redirect to interface with ifindex 3
    return bpf_redirect(3, 0);
}
```

The second argument is flags. Use `BPF_F_INGRESS` to redirect to ingress path instead of egress (for TC programs).

### Using DEVMAP

More efficient for multiple destinations:

```c
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u32);  // ifindex
} tx_ports SEC(".maps");

SEC("xdp")
int xdp_redirect_map(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Select destination based on last byte of dest IP
    __u32 key = ip->daddr & 0xFF;

    // Redirect via map (key -> ifindex)
    return bpf_redirect_map(&tx_ports, key, XDP_PASS);
}
```

### DEVMAP_HASH

Hash map variant for sparse ifindex usage:

```c
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);    // Can be any identifier
    __type(value, __u32);  // ifindex
} tx_hash SEC(".maps");
```

### Running Programs on Redirect

Execute another XDP program on the destination interface:

```c
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, struct bpf_devmap_val);
} tx_with_prog SEC(".maps");

// Value with program fd
struct bpf_devmap_val {
    __u32 ifindex;
    __u32 bpf_prog_fd;  // XDP program to run on egress
};
```

## CPU Redirect

Distribute packet processing across CPUs:

```c
struct {
    __uint(type, BPF_MAP_TYPE_CPUMAP);
    __uint(max_entries, 128);
    __type(key, __u32);
    __type(value, __u32);  // Queue size
} cpu_map SEC(".maps");

SEC("xdp")
int xdp_cpu_balance(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Hash on flow (simple version)
    __u32 hash = ip->saddr ^ ip->daddr;
    __u32 cpu = hash % 4;  // Distribute to CPUs 0-3

    return bpf_redirect_map(&cpu_map, cpu, XDP_PASS);
}
```

Initialize the CPU map from userspace:

```c
// Loader code
for (int cpu = 0; cpu < 4; cpu++) {
    __u32 key = cpu;
    __u32 value = 256;  // Queue size per CPU
    bpf_map_update_elem(cpu_map_fd, &key, &value, BPF_ANY);
}
```

## XDP_TX: Same Interface

Reflect packets back out the same interface:

```c
SEC("xdp")
int xdp_tx(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Swap MAC addresses
    __u8 tmp[ETH_ALEN];
    __builtin_memcpy(tmp, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, tmp, ETH_ALEN);

    return XDP_TX;
}
```

## TC Redirect

### Basic Redirect

```c
SEC("tc")
int tc_redirect(struct __sk_buff *skb) {
    // Redirect to interface 4
    return bpf_redirect(4, 0);
}
```

### Redirect with Flags

```c
// To ingress of destination
return bpf_redirect(ifindex, BPF_F_INGRESS);

// To egress (default)
return bpf_redirect(ifindex, 0);
```

### Redirect Peer (veth)

For veth pairs, skip the normal packet path:

```c
SEC("tc")
int tc_redirect_peer(struct __sk_buff *skb) {
    // Redirect directly to veth peer's ingress
    return bpf_redirect_peer(peer_ifindex, 0);
}
```

This is much faster than regular redirect for container networking.

### Clone Redirect (Mirror)

Copy packets while continuing normal processing:

```c
SEC("tc")
int tc_mirror(struct __sk_buff *skb) {
    // Clone and send to monitoring interface
    bpf_clone_redirect(skb, 10, 0);

    // Original packet continues
    return TC_ACT_OK;
}
```

## Load Balancer Pattern

### Consistent Hashing

```c
struct backend {
    __be32 ip;
    __u8 mac[ETH_ALEN];
    __u32 ifindex;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, struct backend);
} backends SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} tx_ports SEC(".maps");

// Simple hash function
static __always_inline __u32 hash_flow(struct iphdr *ip, struct tcphdr *tcp) {
    return ip->saddr ^ ip->daddr ^ (tcp->source << 16 | tcp->dest);
}

SEC("xdp")
int xdp_lb(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    // Only handle traffic to our VIP (port 80)
    if (tcp->dest != bpf_htons(80))
        return XDP_PASS;

    // Select backend
    __u32 hash = hash_flow(ip, tcp);
    __u32 idx = hash % 4;  // 4 backends

    struct backend *be = bpf_map_lookup_elem(&backends, &idx);
    if (!be)
        return XDP_PASS;

    // Rewrite destination
    ip->daddr = be->ip;
    __builtin_memcpy(eth->h_dest, be->mac, ETH_ALEN);

    // Update checksum (simplified)
    ip->check = 0;
    ip->check = ip_checksum(ip, data_end);

    // Redirect to backend's interface
    return bpf_redirect_map(&tx_ports, idx, XDP_PASS);
}
```

## Socket Redirect

Redirect at the socket layer for proxying:

### SK_SKB Programs

```c
struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} sock_map SEC(".maps");

SEC("sk_skb/stream_parser")
int sk_parser(struct __sk_buff *skb) {
    // Return length of message (for framing)
    return skb->len;
}

SEC("sk_skb/stream_verdict")
int sk_verdict(struct __sk_buff *skb) {
    // Redirect to socket at key 1
    return bpf_sk_redirect_map(skb, &sock_map, 1, 0);
}
```

### SOCKHASH for Hash-Based Lookup

```c
struct sock_key {
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 65536);
    __type(key, struct sock_key);
    __type(value, __u64);
} sock_hash SEC(".maps");

SEC("sk_skb/stream_verdict")
int sk_verdict(struct __sk_buff *skb) {
    struct sock_key key = {
        .saddr = skb->remote_ip4,
        .daddr = skb->local_ip4,
        .sport = skb->remote_port >> 16,
        .dport = (__u16)skb->local_port,
    };

    return bpf_sk_redirect_hash(skb, &sock_hash, &key, 0);
}
```

## XSK: AF_XDP Redirect

For zero-copy userspace packet processing:

```c
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

SEC("xdp")
int xdp_to_userspace(struct xdp_md *ctx) {
    // Redirect to userspace via AF_XDP socket
    __u32 index = ctx->rx_queue_index;
    return bpf_redirect_map(&xsks_map, index, XDP_PASS);
}
```

## Hairpin Mode

Traffic that arrives and leaves on the same interface:

```c
SEC("xdp")
int xdp_hairpin(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Check if this is for our network
    __u32 daddr = bpf_ntohl(ip->daddr);
    if ((daddr >> 24) != 10)  // Not 10.x.x.x
        return XDP_PASS;

    // Look up destination MAC
    __u8 *dst_mac = bpf_map_lookup_elem(&arp_table, &ip->daddr);
    if (!dst_mac)
        return XDP_PASS;

    // Our MAC as source
    __u8 src_mac[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};

    __builtin_memcpy(eth->h_dest, dst_mac, ETH_ALEN);
    __builtin_memcpy(eth->h_source, src_mac, ETH_ALEN);

    // Decrement TTL
    ip->ttl--;
    // Update checksum...

    return XDP_TX;  // Same interface
}
```

## Multi-Path Routing

Distribute traffic across multiple paths:

```c
struct nexthop {
    __u32 ifindex;
    __u8 mac[ETH_ALEN];
    __u8 weight;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, struct nexthop);
} nexthops SEC(".maps");

SEC("xdp")
int xdp_ecmp(struct xdp_md *ctx) {
    // ... parse packet ...

    // ECMP: hash flow to select path
    __u32 hash = ip->saddr ^ ip->daddr ^ ip->protocol;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) <= data_end)
            hash ^= (tcp->source << 16 | tcp->dest);
    }

    __u32 path = hash % 4;  // 4 paths
    struct nexthop *nh = bpf_map_lookup_elem(&nexthops, &path);
    if (!nh)
        return XDP_PASS;

    // Rewrite MAC
    __builtin_memcpy(eth->h_dest, nh->mac, ETH_ALEN);

    return bpf_redirect(nh->ifindex, 0);
}
```

## Debugging Redirect Issues

### Common Problems

1. **Interface doesn't exist**: Check ifindex is valid
2. **XDP not supported on dest**: Some interfaces need generic XDP
3. **MAC not set**: Destination may drop (unknown MAC)
4. **Checksum invalid**: Forgot to update after modification

### Verification

```bash
# Check interface exists
ip link show

# Check XDP attachment
ip link show dev eth0 | grep xdp

# Trace redirects
sudo cat /sys/kernel/debug/tracing/trace_pipe
# (Use bpf_printk in your program)
```

## Exercises

1. **Simple forwarder**: Forward all traffic from eth0 to eth1.

2. **Round-robin LB**: Implement round-robin load balancing across 3 backends.

3. **Traffic mirror**: Mirror HTTP traffic to a monitoring port.

4. **Per-CPU distribution**: Balance incoming traffic across all CPUs based on flow hash.

5. **Conditional redirect**: Redirect SSH traffic to a bastion host, pass others.

6. **Bidirectional proxy**: Use SK_SKB to redirect between two connected sockets.
