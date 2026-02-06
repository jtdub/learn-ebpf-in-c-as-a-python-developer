# Chapter 20: TC Programs

**TC** (Traffic Control) programs attach to the Linux traffic control subsystem, processing packets as they enter or leave a network interface. TC sits between the network driver and the kernel's network stack — a powerful location for packet manipulation.

## TC vs XDP

| Feature | XDP | TC |
|---------|-----|-----|
| Location | Before sk_buff allocation | After sk_buff creation |
| Access | Raw packet data | Full sk_buff metadata |
| Direction | Ingress only | Ingress and egress |
| Performance | Fastest | Very fast |
| Packet modification | Limited | Full support |
| Forwarding | Between interfaces | Flexible redirection |
| Use case | DDoS, load balancing | Firewalls, NAT, shaping |

**When to use TC:**

- You need egress processing
- You need sk_buff metadata (marks, priorities)
- You need to modify packets extensively
- XDP isn't available (e.g., some virtual interfaces)

## TC Architecture

```
                    Ingress Path
        ┌─────────────────────────────────────┐
        │              Driver                 │
        └───────────────┬─────────────────────┘
                        │
                        ▼
        ┌─────────────────────────────────────┐
        │      XDP (if attached)              │
        └───────────────┬─────────────────────┘
                        │
                        ▼
        ┌─────────────────────────────────────┐
        │         sk_buff created             │
        └───────────────┬─────────────────────┘
                        │
                        ▼
        ┌─────────────────────────────────────┐
        │   TC ingress (clsact qdisc)         │  ← TC eBPF here
        └───────────────┬─────────────────────┘
                        │
                        ▼
        ┌─────────────────────────────────────┐
        │         Network Stack               │
        └─────────────────────────────────────┘


                    Egress Path
        ┌─────────────────────────────────────┐
        │         Network Stack               │
        └───────────────┬─────────────────────┘
                        │
                        ▼
        ┌─────────────────────────────────────┐
        │    TC egress (clsact qdisc)         │  ← TC eBPF here
        └───────────────┬─────────────────────┘
                        │
                        ▼
        ┌─────────────────────────────────────┐
        │              Driver                 │
        └─────────────────────────────────────┘
```

## The `__sk_buff` Structure

TC programs receive a `struct __sk_buff` — a subset of the kernel's `sk_buff`:

```c
struct __sk_buff {
    __u32 len;              // Packet length
    __u32 pkt_type;         // Packet type
    __u32 mark;             // Packet mark (can read/write)
    __u32 queue_mapping;    // TX queue
    __u32 protocol;         // L3 protocol (ETH_P_IP, etc.)
    __u32 vlan_present;
    __u32 vlan_tci;
    __u32 vlan_proto;
    __u32 priority;         // QoS priority
    __u32 ingress_ifindex;  // Incoming interface
    __u32 ifindex;          // Interface index
    __u32 tc_index;         // Traffic control index
    __u32 cb[5];            // Control buffer (for your use)
    __u32 hash;             // Packet hash
    __u32 tc_classid;       // TC class ID (can write)
    __u32 data;             // Packet data start
    __u32 data_end;         // Packet data end
    __u32 napi_id;
    __u32 family;           // AF_INET or AF_INET6
    __u32 remote_ip4;       // Remote IPv4 (for sockets)
    __u32 local_ip4;        // Local IPv4
    __u32 remote_ip6[4];    // Remote IPv6
    __u32 local_ip6[4];     // Local IPv6
    __u32 remote_port;      // Remote port
    __u32 local_port;       // Local port
    // ... more fields
};
```

## TC Return Values

```c
#define TC_ACT_OK        0   // Continue processing
#define TC_ACT_SHOT      2   // Drop packet
#define TC_ACT_STOLEN    4   // Consume packet (don't free)
#define TC_ACT_REDIRECT  7   // Redirect to another interface
```

## Basic TC Program

### Packet Counter

=== "libbpf"

    ```c
    // tc_counter.bpf.c
    #include "vmlinux.h"
    #include <bpf/bpf_helpers.h>
    #include <bpf/bpf_endian.h>

    struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __uint(max_entries, 4);
        __type(key, __u32);
        __type(value, __u64);
    } pkt_count SEC(".maps");

    SEC("tc")
    int tc_counter(struct __sk_buff *skb) {
        __u32 idx = 0;  // Total packets

        // Count by protocol
        if (skb->protocol == bpf_htons(ETH_P_IP))
            idx = 1;
        else if (skb->protocol == bpf_htons(ETH_P_IPV6))
            idx = 2;
        else
            idx = 3;

        __u64 *count = bpf_map_lookup_elem(&pkt_count, &idx);
        if (count)
            __sync_fetch_and_add(count, 1);

        return TC_ACT_OK;
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
    #include <linux/pkt_cls.h>
    #include <linux/if_ether.h>

    BPF_PERCPU_ARRAY(pkt_count, u64, 4);

    int tc_counter(struct __sk_buff *skb) {
        u32 idx;

        if (skb->protocol == htons(ETH_P_IP))
            idx = 1;
        else if (skb->protocol == htons(ETH_P_IPV6))
            idx = 2;
        else
            idx = 3;

        u64 *count = pkt_count.lookup(&idx);
        if (count)
            (*count)++;

        return TC_ACT_OK;
    }
    """

    b = BPF(text=program)
    fn = b.load_func("tc_counter", BPF.SCHED_CLS)

    # Note: BCC doesn't directly attach TC, use iproute2 or libbpf
    print("Program loaded. Use 'tc' command to attach:")
    print(f"  tc qdisc add dev {device} clsact")
    print(f"  tc filter add dev {device} ingress bpf da fd {fn.fd}")
    ```

### Attaching TC Programs

Using `iproute2` (the `tc` command):

```bash
# Create clsact qdisc (required once per interface)
sudo tc qdisc add dev eth0 clsact

# Attach to ingress
sudo tc filter add dev eth0 ingress bpf direct-action obj tc_counter.bpf.o sec tc

# Attach to egress
sudo tc filter add dev eth0 egress bpf direct-action obj tc_counter.bpf.o sec tc

# List attached programs
sudo tc filter show dev eth0 ingress
sudo tc filter show dev eth0 egress

# Remove
sudo tc filter del dev eth0 ingress
sudo tc qdisc del dev eth0 clsact
```

!!! note "direct-action"
    The `direct-action` (or `da`) flag tells TC to use the return value from the eBPF program directly as the packet verdict, bypassing the traditional TC action system.

## Packet Filtering

### Simple Firewall

```c
SEC("tc")
int tc_firewall(struct __sk_buff *skb) {
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

    // Drop ICMP
    if (ip->protocol == IPPROTO_ICMP)
        return TC_ACT_SHOT;

    // Drop traffic from 10.0.0.0/8
    __u32 src = bpf_ntohl(ip->saddr);
    if ((src >> 24) == 10)
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}
```

### Port-Based Filtering

```c
SEC("tc")
int tc_port_filter(struct __sk_buff *skb) {
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

    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    __u16 dport = bpf_ntohs(tcp->dest);

    // Block SSH (22) and Telnet (23)
    if (dport == 22 || dport == 23)
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}
```

## Packet Modification

### Setting Marks

Marks can be used by iptables, routing decisions, QoS:

```c
SEC("tc")
int tc_set_mark(struct __sk_buff *skb) {
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

    // Mark packets from 192.168.0.0/16 with mark 100
    __u32 src = bpf_ntohl(ip->saddr);
    if ((src >> 16) == 0xC0A8) {  // 192.168.x.x
        skb->mark = 100;
    }

    return TC_ACT_OK;
}
```

### Modifying Headers

```c
#include <bpf/bpf_helpers.h>

SEC("tc")
int tc_modify_dscp(struct __sk_buff *skb) {
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

    // Set DSCP to EF (Expedited Forwarding) = 46
    __u8 old_tos = ip->tos;
    __u8 new_tos = (46 << 2);  // DSCP is upper 6 bits

    // Update checksum incrementally
    bpf_l3_csum_replace(skb, offsetof(struct iphdr, check),
                        bpf_htons(old_tos), bpf_htons(new_tos), 2);

    // Modify the TOS field
    bpf_skb_store_bytes(skb, ETH_HLEN + offsetof(struct iphdr, tos),
                        &new_tos, sizeof(new_tos), 0);

    return TC_ACT_OK;
}
```

## Traffic Redirection

### Redirect to Another Interface

```c
SEC("tc")
int tc_redirect(struct __sk_buff *skb) {
    // Redirect to interface with ifindex 3
    return bpf_redirect(3, 0);
}
```

### Redirect with Peer (Hairpin)

```c
SEC("tc")
int tc_redirect_peer(struct __sk_buff *skb) {
    // Redirect to peer of a veth pair
    return bpf_redirect_peer(3, 0);
}
```

### Clone and Redirect (Mirror)

```c
SEC("tc")
int tc_mirror(struct __sk_buff *skb) {
    // Clone packet and send to interface 4
    bpf_clone_redirect(skb, 4, 0);

    // Continue processing original
    return TC_ACT_OK;
}
```

## Classification

### Setting TC Class

For use with traffic shaping:

```c
SEC("tc")
int tc_classify(struct __sk_buff *skb) {
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

    // Classify SSH to class 1:10, HTTP to 1:20, rest to 1:30
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;

        __u16 dport = bpf_ntohs(tcp->dest);

        if (dport == 22)
            skb->tc_classid = 0x00010010;  // 1:10
        else if (dport == 80 || dport == 443)
            skb->tc_classid = 0x00010020;  // 1:20
        else
            skb->tc_classid = 0x00010030;  // 1:30
    }

    return TC_ACT_OK;
}
```

Setup the qdisc hierarchy:

```bash
# Create HTB qdisc
sudo tc qdisc add dev eth0 root handle 1: htb default 30

# Create classes
sudo tc class add dev eth0 parent 1: classid 1:10 htb rate 10mbit ceil 100mbit
sudo tc class add dev eth0 parent 1: classid 1:20 htb rate 50mbit ceil 100mbit
sudo tc class add dev eth0 parent 1: classid 1:30 htb rate 20mbit ceil 100mbit

# Attach classifier
sudo tc filter add dev eth0 parent 1: bpf obj tc_classify.bpf.o sec tc
```

## Checksum Helpers

When modifying packets, update checksums:

```c
// L3 (IP) checksum
bpf_l3_csum_replace(skb, offset, old_value, new_value, size);

// L4 (TCP/UDP) checksum
bpf_l4_csum_replace(skb, offset, old_value, new_value, flags);

// flags:
// BPF_F_PSEUDO_HDR - Include pseudo-header (for TCP/UDP)
// BPF_F_MARK_MANGLED_0 - Mark as 0 if result is 0
```

Example — changing destination IP:

```c
SEC("tc")
int tc_dnat(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    __be32 old_daddr = ip->daddr;
    __be32 new_daddr = bpf_htonl(0x0A000001);  // 10.0.0.1

    // Update L3 checksum
    bpf_l3_csum_replace(skb, ETH_HLEN + offsetof(struct iphdr, check),
                        old_daddr, new_daddr, 4);

    // Update L4 checksum (if TCP/UDP)
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;

        bpf_l4_csum_replace(skb, ETH_HLEN + (ip->ihl * 4) + offsetof(struct tcphdr, check),
                            old_daddr, new_daddr, 4 | BPF_F_PSEUDO_HDR);
    }

    // Write new address
    bpf_skb_store_bytes(skb, ETH_HLEN + offsetof(struct iphdr, daddr),
                        &new_daddr, sizeof(new_daddr), 0);

    return TC_ACT_OK;
}
```

## TC Programs with libbpf

### Loader Code

```c
// tc_loader.c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include "tc_counter.skel.h"

static volatile bool running = true;

static void sig_handler(int sig) { running = false; }

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    const char *ifname = argv[1];
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        perror("if_nametoindex");
        return 1;
    }

    signal(SIGINT, sig_handler);

    struct tc_counter_bpf *skel = tc_counter_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load BPF program\n");
        return 1;
    }

    // Attach using tc hook
    LIBBPF_OPTS(bpf_tc_hook, hook,
        .ifindex = ifindex,
        .attach_point = BPF_TC_INGRESS,
    );

    int err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST) {
        fprintf(stderr, "Failed to create TC hook: %d\n", err);
        goto cleanup;
    }

    LIBBPF_OPTS(bpf_tc_opts, opts,
        .prog_fd = bpf_program__fd(skel->progs.tc_counter),
    );

    err = bpf_tc_attach(&hook, &opts);
    if (err) {
        fprintf(stderr, "Failed to attach TC: %d\n", err);
        goto cleanup;
    }

    printf("Attached to %s. Press Ctrl+C to exit.\n", ifname);

    while (running) {
        sleep(1);
        // Read and print stats...
    }

    // Detach
    opts.flags = opts.prog_fd = opts.prog_id = 0;
    bpf_tc_detach(&hook, &opts);

cleanup:
    hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;
    bpf_tc_hook_destroy(&hook);
    tc_counter_bpf__destroy(skel);
    return err != 0;
}
```

## Exercises

1. **Bandwidth counter**: Count bytes (not just packets) per protocol on egress.

2. **Rate display**: Build on the counter to show Mbps in real-time.

3. **Egress firewall**: Block outgoing connections to a configurable list of IPs.

4. **DSCP marker**: Set different DSCP values based on destination port.

5. **Traffic mirror**: Mirror all HTTP traffic to a monitoring interface.

6. **Simple load balancer**: Redirect packets to different backends based on source IP hash.
