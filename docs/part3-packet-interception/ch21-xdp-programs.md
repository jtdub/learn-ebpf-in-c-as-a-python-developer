# Chapter 21: XDP Programs

**XDP** (eXpress Data Path) processes packets at the earliest possible point — right as they're received by the network driver, before the kernel allocates any metadata structures. This makes XDP the fastest packet processing path in Linux.

## Why XDP?

| Feature | XDP Advantage |
|---------|---------------|
| Speed | Process millions of packets per second |
| Location | Before sk_buff allocation (zero-copy possible) |
| Use cases | DDoS mitigation, load balancing, packet filtering |
| Overhead | Minimal — no memory allocation per packet |

## XDP Modes

XDP can run in three modes:

| Mode | Description | Performance | Requirements |
|------|-------------|-------------|--------------|
| Native | In NIC driver | Fastest | Driver support |
| Offloaded | On NIC hardware | Even faster | Smart NIC |
| Generic | In network stack | Slowest | Any interface |

Check driver support:

```bash
# Native XDP support?
ethtool -i eth0 | grep driver
# Then check: Does that driver support XDP?
```

Common drivers with native XDP: `i40e`, `ixgbe`, `mlx5`, `virtio_net`, `veth`.

## XDP Context: `xdp_md`

```c
struct xdp_md {
    __u32 data;           // Packet data start
    __u32 data_end;       // Packet data end
    __u32 data_meta;      // Metadata area start
    __u32 ingress_ifindex; // Incoming interface
    __u32 rx_queue_index; // RX queue
    __u32 egress_ifindex; // For bpf_redirect_map
};
```

Unlike TC programs, XDP has minimal context — just the raw packet.

## XDP Return Values

```c
#define XDP_ABORTED  0  // Error, drop + trace
#define XDP_DROP     1  // Drop silently
#define XDP_PASS     2  // Pass to network stack
#define XDP_TX       3  // Send back out same interface
#define XDP_REDIRECT 4  // Redirect to another interface/CPU
```

## Basic XDP Program

### Packet Counter

=== "libbpf"

    ```c
    // xdp_counter.bpf.c
    #include "vmlinux.h"
    #include <bpf/bpf_helpers.h>
    #include <bpf/bpf_endian.h>

    struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __uint(max_entries, 256);
        __type(key, __u32);
        __type(value, __u64);
    } proto_count SEC(".maps");

    SEC("xdp")
    int xdp_counter(struct xdp_md *ctx) {
        void *data = (void *)(long)ctx->data;
        void *data_end = (void *)(long)ctx->data_end;

        struct ethhdr *eth = data;
        if ((void *)(eth + 1) > data_end)
            return XDP_PASS;

        __u32 proto = bpf_ntohs(eth->h_proto);
        __u64 *count = bpf_map_lookup_elem(&proto_count, &proto);
        if (count)
            __sync_fetch_and_add(count, 1);

        return XDP_PASS;
    }

    char LICENSE[] SEC("license") = "GPL";
    ```

=== "BCC"

    ```python
    #!/usr/bin/env python3
    from bcc import BPF
    from time import sleep
    import sys

    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <interface>")
        sys.exit(1)

    device = sys.argv[1]

    program = r"""
    #include <linux/bpf.h>
    #include <linux/if_ether.h>

    BPF_PERCPU_ARRAY(proto_count, u64, 256);

    int xdp_counter(struct xdp_md *ctx) {
        void *data = (void *)(long)ctx->data;
        void *data_end = (void *)(long)ctx->data_end;

        struct ethhdr *eth = data;
        if ((void *)(eth + 1) > data_end)
            return XDP_PASS;

        u32 proto = ntohs(eth->h_proto);
        u64 *count = proto_count.lookup(&proto);
        if (count)
            (*count)++;

        return XDP_PASS;
    }
    """

    b = BPF(text=program)
    fn = b.load_func("xdp_counter", BPF.XDP)
    b.attach_xdp(device, fn, 0)

    print(f"Counting on {device}. Ctrl+C to exit.")
    proto_names = {0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6"}

    try:
        while True:
            sleep(1)
            print("\033[2J\033[H")  # Clear screen
            print(f"{'Protocol':<10} {'Count':>15}")
            print("-" * 26)
            for proto, values in b["proto_count"].items():
                total = sum(values)
                if total > 0:
                    name = proto_names.get(proto.value, hex(proto.value))
                    print(f"{name:<10} {total:>15}")
    except KeyboardInterrupt:
        pass

    b.remove_xdp(device)
    ```

### Attaching XDP

Using iproute2:

```bash
# Attach (native mode)
sudo ip link set dev eth0 xdp obj xdp_counter.bpf.o sec xdp

# Attach (generic/skb mode, for testing)
sudo ip link set dev eth0 xdpgeneric obj xdp_counter.bpf.o sec xdp

# Check
ip link show eth0
# ... xdp/id:123

# Detach
sudo ip link set dev eth0 xdp off
```

Using bpftool:

```bash
sudo bpftool net attach xdp id 123 dev eth0
sudo bpftool net detach xdp dev eth0
```

## Packet Parsing

### Ethernet + IP + TCP

```c
SEC("xdp")
int xdp_parse(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Only handle IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Only handle TCP
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // TCP header (variable IP header length!)
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    // Now we can access TCP fields
    __u16 dest_port = bpf_ntohs(tcp->dest);

    if (dest_port == 80)
        bpf_printk("HTTP packet!\n");

    return XDP_PASS;
}
```

### VLAN-Aware Parsing

```c
SEC("xdp")
int xdp_vlan(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 h_proto = eth->h_proto;
    void *cursor = (void *)(eth + 1);

    // Check for VLAN tag
    if (h_proto == bpf_htons(ETH_P_8021Q) ||
        h_proto == bpf_htons(ETH_P_8021AD)) {
        struct vlan_hdr {
            __be16 tci;
            __be16 proto;
        } *vlan = cursor;

        if ((void *)(vlan + 1) > data_end)
            return XDP_PASS;

        h_proto = vlan->proto;
        cursor = (void *)(vlan + 1);
    }

    // Now h_proto is the actual protocol
    if (h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = cursor;
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;
        // Process IP...
    }

    return XDP_PASS;
}
```

## DDoS Mitigation

### Drop by IP

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);    // IP address
    __type(value, __u8);   // 1 = blocked
} blocklist SEC(".maps");

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
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

    __u32 src = ip->saddr;
    __u8 *blocked = bpf_map_lookup_elem(&blocklist, &src);
    if (blocked)
        return XDP_DROP;

    return XDP_PASS;
}
```

### Rate Limiting

```c
struct rate_info {
    __u64 tokens;
    __u64 last_update;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct rate_info);
} rate_limit SEC(".maps");

#define RATE_LIMIT 1000  // packets per second
#define BUCKET_SIZE 100  // burst size

SEC("xdp")
int xdp_rate_limit(struct xdp_md *ctx) {
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

    __u32 src = ip->saddr;
    __u64 now = bpf_ktime_get_ns();

    struct rate_info *info = bpf_map_lookup_elem(&rate_limit, &src);
    if (!info) {
        struct rate_info new_info = {
            .tokens = BUCKET_SIZE - 1,
            .last_update = now,
        };
        bpf_map_update_elem(&rate_limit, &src, &new_info, BPF_ANY);
        return XDP_PASS;
    }

    // Token bucket algorithm
    __u64 elapsed = now - info->last_update;
    __u64 refill = elapsed * RATE_LIMIT / 1000000000ULL;
    info->tokens += refill;
    if (info->tokens > BUCKET_SIZE)
        info->tokens = BUCKET_SIZE;
    info->last_update = now;

    if (info->tokens > 0) {
        info->tokens--;
        return XDP_PASS;
    }

    return XDP_DROP;  // Rate exceeded
}
```

## XDP_TX: Packet Reflection

Send packets back out the same interface:

```c
// Swap MAC addresses
static __always_inline void swap_mac(struct ethhdr *eth) {
    __u8 tmp[ETH_ALEN];
    __builtin_memcpy(tmp, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, tmp, ETH_ALEN);
}

SEC("xdp")
int xdp_reflect(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    swap_mac(eth);
    return XDP_TX;  // Send back out
}
```

### ICMP Echo Responder

```c
SEC("xdp")
int xdp_ping_responder(struct xdp_md *ctx) {
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

    if (ip->protocol != IPPROTO_ICMP)
        return XDP_PASS;

    struct icmphdr *icmp = (void *)ip + (ip->ihl * 4);
    if ((void *)(icmp + 1) > data_end)
        return XDP_PASS;

    // Only respond to echo requests
    if (icmp->type != ICMP_ECHO)
        return XDP_PASS;

    // Swap MACs
    __u8 tmp_mac[ETH_ALEN];
    __builtin_memcpy(tmp_mac, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

    // Swap IPs
    __u32 tmp_ip = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp_ip;

    // Change ICMP type to reply
    icmp->type = ICMP_ECHOREPLY;

    // Update ICMP checksum (type changed from 8 to 0)
    icmp->checksum += bpf_htons(8);

    return XDP_TX;
}
```

## XDP Redirect

### Redirect to Another Interface

```c
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u32);
} tx_port SEC(".maps");

SEC("xdp")
int xdp_redirect(struct xdp_md *ctx) {
    // Redirect to interface in map entry 0
    return bpf_redirect_map(&tx_port, 0, 0);
}
```

Populate the map from userspace:

```c
// In loader
__u32 key = 0;
__u32 ifindex = if_nametoindex("eth1");
bpf_map_update_elem(map_fd, &key, &ifindex, BPF_ANY);
```

### CPU Redirect (Load Balancing)

```c
struct {
    __uint(type, BPF_MAP_TYPE_CPUMAP);
    __uint(max_entries, 128);
    __type(key, __u32);
    __type(value, __u32);
} cpu_map SEC(".maps");

SEC("xdp")
int xdp_cpu_redirect(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Hash on source MAC to pick CPU
    __u32 hash = eth->h_source[5];
    __u32 cpu = hash % 4;  // Distribute across 4 CPUs

    return bpf_redirect_map(&cpu_map, cpu, 0);
}
```

## XDP Metadata

Pass data to TC or network stack:

```c
SEC("xdp")
int xdp_with_meta(struct xdp_md *ctx) {
    // Reserve metadata space
    int ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(__u32));
    if (ret < 0)
        return XDP_PASS;

    void *data = (void *)(long)ctx->data;
    void *data_meta = (void *)(long)ctx->data_meta;

    if (data_meta + sizeof(__u32) > data)
        return XDP_PASS;

    // Store metadata
    __u32 *meta = data_meta;
    *meta = 0x12345678;  // Custom mark

    return XDP_PASS;
}

// TC program can read metadata
SEC("tc")
int tc_read_meta(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_meta = (void *)(long)skb->data_meta;

    if (data_meta + sizeof(__u32) > data)
        return TC_ACT_OK;

    __u32 *meta = data_meta;
    if (*meta == 0x12345678) {
        // This packet was processed by XDP
        skb->mark = *meta;
    }

    return TC_ACT_OK;
}
```

## Packet Modification

### Adjust Head (Add/Remove Headers)

```c
SEC("xdp")
int xdp_encap(struct xdp_md *ctx) {
    // Make room for a new header
    int ret = bpf_xdp_adjust_head(ctx, -14);  // Add 14 bytes
    if (ret < 0)
        return XDP_DROP;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Now fill in the new header...
    struct ethhdr *new_eth = data;
    if ((void *)(new_eth + 1) > data_end)
        return XDP_DROP;

    // Set new ethernet header
    // ...

    return XDP_TX;
}
```

## Performance Tips

1. **Use native mode** when possible (not generic)

2. **Minimize map lookups** — batch or reduce

3. **Use per-CPU maps** for counters

4. **Avoid unnecessary parsing** — check protocol early

5. **Use `__always_inline`** for helper functions

6. **Keep it simple** — complex programs reduce performance

## Common Patterns

### Lookup Table (LPM)

```c
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 10000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key);
    __type(value, __u8);
} lpm SEC(".maps");

struct lpm_key {
    __u32 prefixlen;
    __u32 addr;
};

SEC("xdp")
int xdp_lpm(struct xdp_md *ctx) {
    // ... parse to get IP ...

    struct lpm_key key = {
        .prefixlen = 32,
        .addr = ip->saddr,
    };

    __u8 *action = bpf_map_lookup_elem(&lpm, &key);
    if (action && *action == 1)
        return XDP_DROP;

    return XDP_PASS;
}
```

## Exercises

1. **Protocol stats**: Count packets and bytes per IP protocol (TCP, UDP, ICMP, other).

2. **SYN flood protection**: Drop TCP SYN packets over a threshold from any single IP.

3. **Port scanner detection**: Detect and block IPs that probe multiple ports rapidly.

4. **Load balancer**: Distribute incoming packets across multiple backend servers using consistent hashing.

5. **Packet logger**: Pass metadata to TC with packet timestamps for userspace logging.

6. **NAT**: Implement source NAT for outgoing packets (rewrite source IP).
