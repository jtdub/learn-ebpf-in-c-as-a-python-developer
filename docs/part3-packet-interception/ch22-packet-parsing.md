# Chapter 22: Packet Parsing

Safe packet parsing is the foundation of any network eBPF program. The verifier is strict: every byte access must be bounds-checked. This chapter covers robust parsing patterns.

## The Parsing Challenge

Every packet access needs bounds validation:

```c
// WRONG - Will fail verification
struct iphdr *ip = data + sizeof(struct ethhdr);
__u8 ttl = ip->ttl;  // ERROR: ip might be past data_end

// CORRECT
struct iphdr *ip = data + sizeof(struct ethhdr);
if ((void *)(ip + 1) > data_end)
    return XDP_PASS;
__u8 ttl = ip->ttl;  // OK: we verified bounds
```

## Basic Parsing Pattern

```c
SEC("xdp")
int parse_packet(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Layer 2: Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Check EtherType
    __u16 h_proto = eth->h_proto;

    // Layer 3: IP (if IPv4)
    if (h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Layer 4: TCP/UDP
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        // Now safe to access tcp fields
    }

    return XDP_PASS;
}
```

## Cursor-Based Parsing

Use a cursor for cleaner code:

```c
struct cursor {
    void *pos;
    void *end;
};

static __always_inline int cursor_advance(struct cursor *c, int len) {
    void *new_pos = c->pos + len;
    if (new_pos > c->end)
        return -1;
    c->pos = new_pos;
    return 0;
}

SEC("xdp")
int parse_with_cursor(struct xdp_md *ctx) {
    struct cursor c;
    c.pos = (void *)(long)ctx->data;
    c.end = (void *)(long)ctx->data_end;

    // Ethernet
    struct ethhdr *eth = c.pos;
    if (cursor_advance(&c, sizeof(*eth)))
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // IP
    struct iphdr *ip = c.pos;
    if (cursor_advance(&c, sizeof(*ip)))
        return XDP_PASS;

    // Skip IP options
    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len > sizeof(*ip)) {
        if (cursor_advance(&c, ip_hdr_len - sizeof(*ip)))
            return XDP_PASS;
    }

    // Now c.pos points to L4 header
    return XDP_PASS;
}
```

## Parsing Common Protocols

### Ethernet (Layer 2)

```c
struct ethhdr {
    unsigned char h_dest[ETH_ALEN];    // Destination MAC
    unsigned char h_source[ETH_ALEN];  // Source MAC
    __be16 h_proto;                    // Protocol (ETH_P_*)
};
```

Common EtherTypes:

| Constant | Value | Protocol |
|----------|-------|----------|
| `ETH_P_IP` | 0x0800 | IPv4 |
| `ETH_P_IPV6` | 0x86DD | IPv6 |
| `ETH_P_ARP` | 0x0806 | ARP |
| `ETH_P_8021Q` | 0x8100 | VLAN |
| `ETH_P_8021AD` | 0x88A8 | QinQ (double VLAN) |

### VLAN Headers

```c
struct vlan_hdr {
    __be16 h_vlan_TCI;     // Priority (3) + CFI (1) + VLAN ID (12)
    __be16 h_vlan_encapsulated_proto;
};

static __always_inline int parse_vlan(void **data, void *data_end,
                                      __u16 *proto) {
    struct vlan_hdr *vlan = *data;
    if ((void *)(vlan + 1) > data_end)
        return -1;

    *proto = vlan->h_vlan_encapsulated_proto;
    *data = (void *)(vlan + 1);
    return 0;
}

SEC("xdp")
int parse_vlan_packet(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 h_proto = eth->h_proto;
    void *cursor = (void *)(eth + 1);

    // Handle up to 2 VLAN tags
    #pragma unroll
    for (int i = 0; i < 2; i++) {
        if (h_proto == bpf_htons(ETH_P_8021Q) ||
            h_proto == bpf_htons(ETH_P_8021AD)) {
            if (parse_vlan(&cursor, data_end, &h_proto) < 0)
                return XDP_PASS;
        }
    }

    // Now h_proto is the real protocol, cursor is past VLANs
    return XDP_PASS;
}
```

### IPv4 (Layer 3)

```c
struct iphdr {
    __u8    ihl:4,          // Header length (in 32-bit words)
            version:4;      // Always 4
    __u8    tos;            // Type of service
    __be16  tot_len;        // Total length
    __be16  id;             // Identification
    __be16  frag_off;       // Fragment offset + flags
    __u8    ttl;            // Time to live
    __u8    protocol;       // Next protocol (IPPROTO_*)
    __sum16 check;          // Checksum
    __be32  saddr;          // Source address
    __be32  daddr;          // Destination address
    // Options follow if ihl > 5
};
```

**Important**: The IP header can have variable length (20-60 bytes). Always use `ip->ihl * 4`:

```c
struct iphdr *ip = data + sizeof(struct ethhdr);
if ((void *)(ip + 1) > data_end)
    return XDP_PASS;

// Calculate actual header length
__u32 ip_hdr_len = ip->ihl * 4;
if (ip_hdr_len < sizeof(*ip))
    return XDP_PASS;  // Invalid

// Bounds check the full IP header
if ((void *)ip + ip_hdr_len > data_end)
    return XDP_PASS;

// L4 header starts after IP options
void *l4_hdr = (void *)ip + ip_hdr_len;
```

### IPv6 (Layer 3)

```c
struct ipv6hdr {
    __u8    version:4,      // Always 6
            priority:4;
    __u8    flow_lbl[3];    // Flow label
    __be16  payload_len;    // Payload length (not including header)
    __u8    nexthdr;        // Next header (like protocol in IPv4)
    __u8    hop_limit;      // Like TTL
    struct in6_addr saddr;  // Source (128 bits)
    struct in6_addr daddr;  // Destination (128 bits)
};
```

IPv6 parsing is more complex due to extension headers:

```c
// Simple parsing (ignoring extension headers)
SEC("xdp")
int parse_ipv6_simple(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return XDP_PASS;

    struct ipv6hdr *ip6 = (void *)(eth + 1);
    if ((void *)(ip6 + 1) > data_end)
        return XDP_PASS;

    // nexthdr might be extension header, not transport
    __u8 nexthdr = ip6->nexthdr;

    // For real use, iterate through extension headers
    // This is simplified:
    if (nexthdr == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip6 + 1);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        // Process TCP...
    }

    return XDP_PASS;
}
```

### TCP (Layer 4)

```c
struct tcphdr {
    __be16  source;     // Source port
    __be16  dest;       // Destination port
    __be32  seq;        // Sequence number
    __be32  ack_seq;    // Acknowledgment number
    __u16   res1:4,     // Reserved
            doff:4,     // Data offset (header length in 32-bit words)
            fin:1,      // FIN flag
            syn:1,      // SYN flag
            rst:1,      // RST flag
            psh:1,      // PSH flag
            ack:1,      // ACK flag
            urg:1,      // URG flag
            ece:1,      // ECE flag
            cwr:1;      // CWR flag
    __be16  window;     // Window size
    __sum16 check;      // Checksum
    __be16  urg_ptr;    // Urgent pointer
    // Options follow if doff > 5
};
```

```c
static __always_inline struct tcphdr *parse_tcp(void *data, void *data_end,
                                                 struct iphdr *ip) {
    __u32 ip_hdr_len = ip->ihl * 4;
    struct tcphdr *tcp = data + sizeof(struct ethhdr) + ip_hdr_len;

    if ((void *)(tcp + 1) > data_end)
        return NULL;

    return tcp;
}

// Access TCP payload
static __always_inline void *tcp_payload(struct tcphdr *tcp, void *data_end) {
    __u32 tcp_hdr_len = tcp->doff * 4;
    void *payload = (void *)tcp + tcp_hdr_len;

    if (payload > data_end)
        return NULL;

    return payload;
}
```

### UDP (Layer 4)

```c
struct udphdr {
    __be16  source;     // Source port
    __be16  dest;       // Destination port
    __be16  len;        // Length (header + data)
    __sum16 check;      // Checksum
};
```

UDP is simpler — fixed 8-byte header:

```c
static __always_inline struct udphdr *parse_udp(void *data, void *data_end,
                                                 struct iphdr *ip) {
    __u32 ip_hdr_len = ip->ihl * 4;
    struct udphdr *udp = data + sizeof(struct ethhdr) + ip_hdr_len;

    if ((void *)(udp + 1) > data_end)
        return NULL;

    return udp;
}
```

### ICMP (Layer 4)

```c
struct icmphdr {
    __u8    type;       // Message type
    __u8    code;       // Message code
    __sum16 checksum;   // Checksum
    union {
        struct {
            __be16  id;
            __be16  sequence;
        } echo;
        __be32  gateway;
        struct {
            __be16  __unused;
            __be16  mtu;
        } frag;
    } un;
};
```

Common ICMP types:

| Type | Name |
|------|------|
| 0 | Echo Reply |
| 3 | Destination Unreachable |
| 8 | Echo Request |
| 11 | Time Exceeded |

### ARP

```c
struct arphdr {
    __be16  ar_hrd;     // Hardware type (1 = Ethernet)
    __be16  ar_pro;     // Protocol type (0x0800 = IPv4)
    __u8    ar_hln;     // Hardware address length (6 for MAC)
    __u8    ar_pln;     // Protocol address length (4 for IPv4)
    __be16  ar_op;      // Operation (1 = request, 2 = reply)
};

// For Ethernet/IPv4 ARP:
struct arp_eth_ipv4 {
    unsigned char ar_sha[ETH_ALEN];  // Sender hardware address
    __be32 ar_sip;                   // Sender protocol address
    unsigned char ar_tha[ETH_ALEN];  // Target hardware address
    __be32 ar_tip;                   // Target protocol address
};
```

## Complete Parser Example

```c
struct packet_info {
    __u16 l3_proto;      // ETH_P_*
    __u8  l4_proto;      // IPPROTO_*
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
};

static __always_inline int parse_packet_info(struct xdp_md *ctx,
                                              struct packet_info *info) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Initialize
    __builtin_memset(info, 0, sizeof(*info));

    // Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    __u16 h_proto = eth->h_proto;
    void *cursor = (void *)(eth + 1);

    // Skip VLAN
    if (h_proto == bpf_htons(ETH_P_8021Q)) {
        struct vlan_hdr *vlan = cursor;
        if ((void *)(vlan + 1) > data_end)
            return -1;
        h_proto = vlan->h_vlan_encapsulated_proto;
        cursor = (void *)(vlan + 1);
    }

    info->l3_proto = bpf_ntohs(h_proto);

    // IPv4
    if (h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = cursor;
        if ((void *)(ip + 1) > data_end)
            return -1;

        info->l4_proto = ip->protocol;
        info->src_ip = ip->saddr;
        info->dst_ip = ip->daddr;

        __u32 ip_hdr_len = ip->ihl * 4;
        if (ip_hdr_len < 20 || (void *)ip + ip_hdr_len > data_end)
            return -1;

        cursor = (void *)ip + ip_hdr_len;

        // TCP
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = cursor;
            if ((void *)(tcp + 1) > data_end)
                return -1;
            info->src_port = tcp->source;
            info->dst_port = tcp->dest;
        }
        // UDP
        else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = cursor;
            if ((void *)(udp + 1) > data_end)
                return -1;
            info->src_port = udp->source;
            info->dst_port = udp->dest;
        }
    }

    return 0;
}

SEC("xdp")
int xdp_parse_all(struct xdp_md *ctx) {
    struct packet_info pkt;

    if (parse_packet_info(ctx, &pkt) < 0)
        return XDP_PASS;

    // Now use pkt.src_ip, pkt.dst_port, etc.
    if (pkt.l4_proto == IPPROTO_TCP &&
        bpf_ntohs(pkt.dst_port) == 22) {
        // SSH packet
        return XDP_DROP;
    }

    return XDP_PASS;
}
```

## Accessing Payload

```c
static __always_inline void *get_tcp_payload(struct xdp_md *ctx,
                                              struct iphdr *ip,
                                              struct tcphdr *tcp,
                                              __u32 *payload_len) {
    void *data_end = (void *)(long)ctx->data_end;

    __u32 ip_hdr_len = ip->ihl * 4;
    __u32 tcp_hdr_len = tcp->doff * 4;

    void *payload = (void *)tcp + tcp_hdr_len;
    if (payload > data_end)
        return NULL;

    __u32 ip_total_len = bpf_ntohs(ip->tot_len);
    *payload_len = ip_total_len - ip_hdr_len - tcp_hdr_len;

    // Verify we have payload_len bytes available
    if (payload + *payload_len > data_end)
        *payload_len = data_end - payload;

    return payload;
}
```

## Byte Order Reminder

Network data is big-endian. Use conversion functions:

```c
// Convert host to network
__be16 port_be = bpf_htons(80);
__be32 ip_be = bpf_htonl(0xC0A80001);  // 192.168.0.1

// Convert network to host
__u16 port = bpf_ntohs(tcp->dest);
__u32 ip = bpf_ntohl(iph->saddr);
```

## Common Verifier Errors

### "invalid access to packet"

```c
// WRONG: No bounds check
struct tcphdr *tcp = (void *)(eth + 1);
return tcp->dest;  // ERROR

// RIGHT: Check bounds
struct tcphdr *tcp = (void *)(eth + 1);
if ((void *)(tcp + 1) > data_end)
    return XDP_PASS;
return tcp->dest;  // OK
```

### "unbounded variable offset"

```c
// WRONG: Variable offset
struct iphdr *ip = data + offset;  // offset from somewhere
if ((void *)(ip + 1) > data_end)
    return XDP_PASS;
// Still might fail if offset wasn't bounded

// RIGHT: Bound the offset first
if (offset > 100)
    return XDP_PASS;
struct iphdr *ip = data + offset;
```

## Exercises

1. **Multi-protocol parser**: Write a parser that handles IPv4 TCP, IPv4 UDP, IPv6 TCP, and IPv6 UDP, storing all info in a unified structure.

2. **DNS parser**: Parse DNS queries (UDP port 53) and extract the queried domain name.

3. **HTTP method detection**: Parse TCP payload to detect HTTP methods (GET, POST, etc.).

4. **VLAN stripper**: Parse double-tagged VLAN packets and extract both VLAN IDs.

5. **ICMP classifier**: Parse ICMP packets and count by type (echo, unreachable, etc.).

6. **Fragmentation detector**: Detect fragmented IPv4 packets and log fragment offset.
