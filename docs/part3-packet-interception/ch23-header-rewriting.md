# Chapter 23: Header Rewriting

Modifying packet headers is essential for NAT, load balancing, tunneling, and traffic manipulation. This chapter covers safe header modification techniques for eBPF.

## The Challenge

Modifying packets requires:

1. **Bounds checking** — Can't write past packet end
2. **Checksum updates** — IP, TCP, UDP checksums must stay valid
3. **Correct byte order** — Network byte order for headers

## Modifying Fields in Place

### Simple Field Changes

```c
SEC("xdp")
int modify_ttl(struct xdp_md *ctx) {
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

    // Decrement TTL (like a router)
    if (ip->ttl <= 1)
        return XDP_DROP;  // TTL expired

    // Update checksum for TTL change
    __u16 old_ttl = ip->ttl;
    ip->ttl--;
    __u16 new_ttl = ip->ttl;

    // Incremental checksum update
    __u32 csum = (~ip->check) & 0xFFFF;
    csum += (~old_ttl) & 0xFFFF;
    csum += new_ttl;
    csum = (csum & 0xFFFF) + (csum >> 16);
    ip->check = ~csum;

    return XDP_PASS;
}
```

## Checksum Calculations

### IP Header Checksum

The IP checksum covers only the IP header:

```c
static __always_inline __u16 ip_checksum(struct iphdr *ip, void *data_end) {
    __u32 sum = 0;
    __u16 *p = (__u16 *)ip;

    // IP header is ihl * 4 bytes = ihl * 2 16-bit words
    int words = ip->ihl * 2;

    // Clear checksum field before calculating
    ip->check = 0;

    #pragma unroll
    for (int i = 0; i < 10; i++) {  // Max 20 words (40 bytes)
        if (i >= words)
            break;
        if ((void *)(p + 1) > data_end)
            return 0;
        sum += *p++;
    }

    // Fold 32-bit sum to 16 bits
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return ~sum;
}
```

### Incremental Checksum Update

Faster than recalculating — update when changing specific fields:

```c
// Update checksum when a 16-bit value changes
static __always_inline void update_csum(__sum16 *csum, __u16 old, __u16 new) {
    __u32 sum = (~*csum) & 0xFFFF;
    sum += (~old) & 0xFFFF;
    sum += new;
    sum = (sum & 0xFFFF) + (sum >> 16);
    *csum = ~sum;
}

// Update checksum when a 32-bit value changes
static __always_inline void update_csum32(__sum16 *csum, __u32 old, __u32 new) {
    update_csum(csum, old >> 16, new >> 16);
    update_csum(csum, old & 0xFFFF, new & 0xFFFF);
}
```

### TCP/UDP Checksum

TCP/UDP checksums include a pseudo-header with IP addresses:

```c
// Using BPF helpers (TC programs)
bpf_l3_csum_replace(skb, IP_CSUM_OFFSET, old_val, new_val, sizeof(old_val));
bpf_l4_csum_replace(skb, TCP_CSUM_OFFSET, old_val, new_val,
                    sizeof(old_val) | BPF_F_PSEUDO_HDR);
```

For XDP, you must calculate manually:

```c
static __always_inline void update_tcp_csum(struct tcphdr *tcp,
                                            __be32 old_ip, __be32 new_ip,
                                            __be16 old_port, __be16 new_port) {
    __u32 sum = (~tcp->check) & 0xFFFF;

    // Remove old values
    sum += (~(old_ip >> 16)) & 0xFFFF;
    sum += (~(old_ip & 0xFFFF)) & 0xFFFF;
    sum += (~old_port) & 0xFFFF;

    // Add new values
    sum += (new_ip >> 16);
    sum += (new_ip & 0xFFFF);
    sum += new_port;

    // Fold
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);

    tcp->check = ~sum;
}
```

## Network Address Translation (NAT)

### Source NAT (SNAT)

Change source IP (for outgoing traffic):

```c
struct nat_entry {
    __be32 new_ip;
    __be16 new_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __be32);      // Original source IP
    __type(value, struct nat_entry);
} snat_table SEC(".maps");

SEC("xdp")
int xdp_snat(struct xdp_md *ctx) {
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

    // Lookup NAT entry
    struct nat_entry *nat = bpf_map_lookup_elem(&snat_table, &ip->saddr);
    if (!nat)
        return XDP_PASS;

    __be32 old_saddr = ip->saddr;
    __be32 new_saddr = nat->new_ip;

    // Update IP checksum
    update_csum32(&ip->check, old_saddr, new_saddr);

    // Update source IP
    ip->saddr = new_saddr;

    // Update L4 checksum if TCP/UDP
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        __be16 old_port = tcp->source;
        __be16 new_port = nat->new_port;

        update_tcp_csum(tcp, old_saddr, new_saddr, old_port, new_port);
        tcp->source = new_port;
    }

    return XDP_PASS;
}
```

### Destination NAT (DNAT)

Change destination IP (for incoming traffic):

```c
SEC("xdp")
int xdp_dnat(struct xdp_md *ctx) {
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

    // Example: Redirect traffic to 192.168.1.100 -> 10.0.0.5
    if (ip->daddr != bpf_htonl(0xC0A80164))  // 192.168.1.100
        return XDP_PASS;

    __be32 old_daddr = ip->daddr;
    __be32 new_daddr = bpf_htonl(0x0A000005);  // 10.0.0.5

    // Update IP checksum
    update_csum32(&ip->check, old_daddr, new_daddr);

    // Update destination IP
    ip->daddr = new_daddr;

    // Update TCP/UDP checksum
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        // TCP checksum includes dest IP in pseudo-header
        update_tcp_csum(tcp, old_daddr, new_daddr, 0, 0);
    }

    return XDP_PASS;
}
```

## MAC Address Rewriting

For forwarding, you need correct MAC addresses:

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __be32);           // IP address
    __type(value, __u8[ETH_ALEN]); // MAC address
} arp_table SEC(".maps");

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
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

    // Lookup destination MAC
    __u8 *dst_mac = bpf_map_lookup_elem(&arp_table, &ip->daddr);
    if (!dst_mac)
        return XDP_PASS;  // Unknown destination

    // Our MAC (should be configured)
    __u8 src_mac[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};

    // Rewrite MACs
    __builtin_memcpy(eth->h_dest, dst_mac, ETH_ALEN);
    __builtin_memcpy(eth->h_source, src_mac, ETH_ALEN);

    // Decrement TTL
    if (ip->ttl <= 1)
        return XDP_DROP;

    update_csum(&ip->check, bpf_htons(ip->ttl << 8),
                bpf_htons((ip->ttl - 1) << 8));
    ip->ttl--;

    return XDP_TX;  // Send out same interface
}
```

## Port Rewriting

### Load Balancer Example

```c
struct backend {
    __be32 ip;
    __be16 port;
    __u8 mac[ETH_ALEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, struct backend);
} backends SEC(".maps");

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

    // Only handle traffic to port 80
    if (tcp->dest != bpf_htons(80))
        return XDP_PASS;

    // Select backend based on source IP hash
    __u32 hash = ip->saddr;
    __u32 idx = hash % 4;

    struct backend *be = bpf_map_lookup_elem(&backends, &idx);
    if (!be)
        return XDP_PASS;

    // Store original values
    __be32 old_daddr = ip->daddr;
    __be16 old_dport = tcp->dest;

    // Rewrite destination
    ip->daddr = be->ip;
    tcp->dest = be->port;

    // Update checksums
    update_csum32(&ip->check, old_daddr, be->ip);
    update_tcp_csum(tcp, old_daddr, be->ip, old_dport, be->port);

    // Rewrite MAC for direct routing
    __builtin_memcpy(eth->h_dest, be->mac, ETH_ALEN);

    return XDP_TX;
}
```

## DSCP/TOS Modification

QoS marking:

```c
SEC("xdp")
int xdp_set_dscp(struct xdp_md *ctx) {
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

    // Set DSCP to EF (Expedited Forwarding) = 46
    // DSCP is bits 2-7 of TOS, ECN is bits 0-1
    __u8 old_tos = ip->tos;
    __u8 new_tos = (46 << 2) | (old_tos & 0x03);  // Preserve ECN

    if (old_tos != new_tos) {
        // Update checksum
        update_csum(&ip->check, bpf_htons(old_tos << 8),
                    bpf_htons(new_tos << 8));
        ip->tos = new_tos;
    }

    return XDP_PASS;
}
```

## TC Program Helpers

TC programs have dedicated helpers for modification:

```c
// Store bytes at offset
bpf_skb_store_bytes(skb, offset, &new_val, sizeof(new_val), 0);

// Load bytes from offset
bpf_skb_load_bytes(skb, offset, &val, sizeof(val));

// Update L3 (IP) checksum
bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_val, new_val, sizeof(old_val));

// Update L4 (TCP/UDP) checksum
bpf_l4_csum_replace(skb, L4_CSUM_OFF, old_val, new_val,
                    sizeof(old_val) | BPF_F_PSEUDO_HDR);
```

### TC NAT Example

```c
SEC("tc")
int tc_dnat(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    __be32 old_daddr = ip->daddr;
    __be32 new_daddr = bpf_htonl(0x0A000001);  // 10.0.0.1

    // Use helpers for cleaner code
    bpf_l3_csum_replace(skb, ETH_HLEN + offsetof(struct iphdr, check),
                        old_daddr, new_daddr, 4);

    bpf_skb_store_bytes(skb, ETH_HLEN + offsetof(struct iphdr, daddr),
                        &new_daddr, sizeof(new_daddr), 0);

    // For TCP/UDP, also update L4 checksum
    if (ip->protocol == IPPROTO_TCP) {
        bpf_l4_csum_replace(skb,
                            ETH_HLEN + (ip->ihl * 4) + offsetof(struct tcphdr, check),
                            old_daddr, new_daddr, 4 | BPF_F_PSEUDO_HDR);
    }

    return TC_ACT_OK;
}
```

## Header Insertion/Removal

### XDP: Adjust Head

```c
SEC("xdp")
int xdp_add_header(struct xdp_md *ctx) {
    // Add 20 bytes at the beginning
    int ret = bpf_xdp_adjust_head(ctx, -20);
    if (ret < 0)
        return XDP_DROP;

    // Pointers are now invalid - reload them
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Fill in the new space
    // ...

    return XDP_TX;
}

SEC("xdp")
int xdp_remove_header(struct xdp_md *ctx) {
    // Remove 20 bytes from the beginning
    int ret = bpf_xdp_adjust_head(ctx, 20);
    if (ret < 0)
        return XDP_DROP;

    // Continue with shortened packet
    // ...

    return XDP_PASS;
}
```

### TC: Adjust Room

```c
SEC("tc")
int tc_encap(struct __sk_buff *skb) {
    // Add space for encapsulation header
    int ret = bpf_skb_adjust_room(skb, 20, BPF_ADJ_ROOM_MAC, 0);
    if (ret < 0)
        return TC_ACT_SHOT;

    // Fill in the new header
    // ...

    return TC_ACT_OK;
}
```

## Common Pitfalls

### 1. Forgetting to Update Checksums

```c
// WRONG - Checksum now invalid
ip->saddr = new_addr;

// RIGHT
update_csum32(&ip->check, old_addr, new_addr);
ip->saddr = new_addr;
```

### 2. Wrong Byte Order

```c
// WRONG
if (ip->daddr == 0x0A000001)  // Host byte order

// RIGHT
if (ip->daddr == bpf_htonl(0x0A000001))  // Network byte order
```

### 3. Invalidated Pointers After Adjust

```c
// WRONG
bpf_xdp_adjust_head(ctx, -20);
ip->ttl--;  // ip pointer is INVALID now

// RIGHT
bpf_xdp_adjust_head(ctx, -20);
data = (void *)(long)ctx->data;  // Reload
data_end = (void *)(long)ctx->data_end;
// Re-parse headers
```

## Exercises

1. **Full NAT**: Implement both SNAT and DNAT with connection tracking.

2. **VLAN tagging**: Add/remove VLAN tags from packets.

3. **DSCP remarking**: Mark traffic by destination port (different DSCP for SSH, HTTP, etc.).

4. **TTL modification**: Implement TTL decrement with proper ICMP time exceeded response.

5. **MAC rewriter**: Build an ARP table from observed traffic and use it for forwarding.

6. **IP-in-IP encap**: Encapsulate packets in an IP-in-IP tunnel.
