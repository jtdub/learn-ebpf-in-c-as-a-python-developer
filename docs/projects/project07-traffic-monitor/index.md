# Project 07: Traffic Monitor

Build a comprehensive traffic monitor that combines multiple eBPF program types for full-stack visibility. This project integrates XDP, TC, kprobes, and sock_ops to provide unified packet and connection metrics.

## What You'll Build

A tool that:

- Monitors packets at XDP level (high-speed counters)
- Inspects packets at TC level (full parsing)
- Tracks socket operations (connections, RTT)
- Correlates events across layers
- Provides real-time dashboards

## Learning Objectives

- Coordinate multiple BPF program types
- Use shared maps across programs
- Build correlated metrics
- Create real-time monitoring tools

## Prerequisites

- All previous projects
- Understanding of all program types from Part 2-4

## Architecture

```
                    ┌─────────────────────────────────────┐
                    │         Traffic Monitor              │
                    │    (Unified Userspace Daemon)       │
                    └───────────────┬─────────────────────┘
                                    │
           ┌────────────────────────┼────────────────────────┐
           │                        │                        │
           ▼                        ▼                        ▼
    ┌─────────────┐         ┌─────────────┐         ┌─────────────┐
    │  XDP Stats  │         │  TC Events  │         │ Sock Events │
    │             │         │             │         │             │
    │ Packet cnts │         │  5-tuple    │         │ Connection  │
    │ Byte counts │         │  Payload    │         │ RTT, state  │
    │ Per-CPU     │         │  Protocol   │         │ Per-socket  │
    └──────┬──────┘         └──────┬──────┘         └──────┬──────┘
           │                        │                        │
           └────────────────────────┼────────────────────────┘
                                    │
                         ┌──────────┴──────────┐
                         │    Shared Maps       │
                         │                      │
                         │ • Flow stats         │
                         │ • Active connections │
                         │ • Global counters    │
                         └─────────────────────┘
```

## Project Structure

```
traffic_monitor/
├── Makefile
├── traffic_monitor.h          # Shared definitions
├── xdp_stats.bpf.c           # XDP counter program
├── tc_parser.bpf.c           # TC inspection program
├── sock_tracker.bpf.c        # sock_ops program
├── traffic_monitor.c         # Unified userspace
└── dashboard.py              # Optional TUI dashboard
```

## Step 1: Shared Header

Create `traffic_monitor.h`:

```c
#ifndef __TRAFFIC_MONITOR_H
#define __TRAFFIC_MONITOR_H

// Flow key (5-tuple)
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 pad[3];
};

// Flow statistics
struct flow_stats {
    __u64 packets;
    __u64 bytes;
    __u64 first_seen;
    __u64 last_seen;
    __u32 avg_rtt;
    __u8 state;
    __u8 flags_seen;  // TCP flags OR'd together
};

// Global counters index
enum global_stat {
    STAT_RX_PACKETS = 0,
    STAT_RX_BYTES,
    STAT_TX_PACKETS,
    STAT_TX_BYTES,
    STAT_TCP_PACKETS,
    STAT_UDP_PACKETS,
    STAT_ICMP_PACKETS,
    STAT_OTHER_PACKETS,
    STAT_CONNECTIONS,
    STAT_MAX,
};

// Protocol stats by port
struct port_stats {
    __u64 packets;
    __u64 bytes;
    __u64 connections;
};

// Event types
enum event_type {
    EVENT_PACKET = 1,
    EVENT_CONNECTION,
    EVENT_FLOW_NEW,
    EVENT_FLOW_END,
};

// Unified event structure
struct traffic_event {
    __u64 timestamp;
    struct flow_key flow;
    __u32 pid;
    __u32 len;
    __u16 event_type;
    __u8 direction;  // 0=rx, 1=tx
    __u8 tcp_flags;
    char comm[16];
};

#endif
```

## Step 2: XDP Stats Program

Create `xdp_stats.bpf.c`:

```c
// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "traffic_monitor.h"

char LICENSE[] SEC("license") = "GPL";

#define ETH_P_IP 0x0800

// Global statistics (shared)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} global_stats SEC(".maps");

// Per-flow statistics (shared)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, struct flow_key);
    __type(value, struct flow_stats);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_stats SEC(".maps");

static __always_inline void update_stat(__u32 key, __u64 delta)
{
    __u64 *val = bpf_map_lookup_elem(&global_stats, &key);
    if (val)
        __sync_fetch_and_add(val, delta);
}

SEC("xdp")
int xdp_stats(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u64 pkt_len = data_end - data;

    // Update RX counters
    update_stat(STAT_RX_PACKETS, 1);
    update_stat(STAT_RX_BYTES, pkt_len);

    // Parse Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Update protocol counters
    __u32 proto_stat;
    switch (ip->protocol) {
    case IPPROTO_TCP: proto_stat = STAT_TCP_PACKETS; break;
    case IPPROTO_UDP: proto_stat = STAT_UDP_PACKETS; break;
    case IPPROTO_ICMP: proto_stat = STAT_ICMP_PACKETS; break;
    default: proto_stat = STAT_OTHER_PACKETS;
    }
    update_stat(proto_stat, 1);

    // Build flow key and update flow stats
    struct flow_key key = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .protocol = ip->protocol,
    };

    // Parse transport for ports
    int ip_hdr_len = ip->ihl * 4;
    void *transport = (void *)ip + ip_hdr_len;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = transport;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        key.src_port = bpf_ntohs(tcp->source);
        key.dst_port = bpf_ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = transport;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        key.src_port = bpf_ntohs(udp->source);
        key.dst_port = bpf_ntohs(udp->dest);
    }

    // Update or create flow
    struct flow_stats *stats = bpf_map_lookup_elem(&flow_stats, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->packets, 1);
        __sync_fetch_and_add(&stats->bytes, pkt_len);
        stats->last_seen = bpf_ktime_get_ns();
    } else {
        struct flow_stats new_stats = {
            .packets = 1,
            .bytes = pkt_len,
            .first_seen = bpf_ktime_get_ns(),
            .last_seen = bpf_ktime_get_ns(),
        };
        bpf_map_update_elem(&flow_stats, &key, &new_stats, BPF_ANY);
    }

    return XDP_PASS;
}
```

## Step 3: TC Parser Program

Create `tc_parser.bpf.c`:

```c
// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "traffic_monitor.h"

char LICENSE[] SEC("license") = "GPL";

#define ETH_P_IP 0x0800

// Reference shared maps
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} global_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, struct flow_key);
    __type(value, struct flow_stats);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_stats SEC(".maps");

// Events ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Port statistics
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u16);
    __type(value, struct port_stats);
} port_stats SEC(".maps");

static __always_inline void update_stat(__u32 key, __u64 delta)
{
    __u64 *val = bpf_map_lookup_elem(&global_stats, &key);
    if (val)
        __sync_fetch_and_add(val, delta);
}

static __always_inline int process_packet(struct __sk_buff *skb, __u8 direction)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // Update direction-specific counters
    if (direction == 1) {  // TX
        update_stat(STAT_TX_PACKETS, 1);
        update_stat(STAT_TX_BYTES, skb->len);
    }

    // Parse Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    // Parse IP
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    // Build flow key
    struct flow_key key = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .protocol = ip->protocol,
    };

    __u8 tcp_flags = 0;
    int ip_hdr_len = ip->ihl * 4;
    void *transport = (void *)ip + ip_hdr_len;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = transport;
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;

        key.src_port = bpf_ntohs(tcp->source);
        key.dst_port = bpf_ntohs(tcp->dest);

        // Capture TCP flags
        if (tcp->syn) tcp_flags |= 0x02;
        if (tcp->ack) tcp_flags |= 0x10;
        if (tcp->fin) tcp_flags |= 0x01;
        if (tcp->rst) tcp_flags |= 0x04;
        if (tcp->psh) tcp_flags |= 0x08;

        // Update port stats
        __u16 port = direction ? key.src_port : key.dst_port;
        struct port_stats *ps = bpf_map_lookup_elem(&port_stats, &port);
        if (ps) {
            __sync_fetch_and_add(&ps->packets, 1);
            __sync_fetch_and_add(&ps->bytes, skb->len);
        } else {
            struct port_stats new_ps = {
                .packets = 1,
                .bytes = skb->len,
            };
            bpf_map_update_elem(&port_stats, &port, &new_ps, BPF_ANY);
        }

    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = transport;
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;

        key.src_port = bpf_ntohs(udp->source);
        key.dst_port = bpf_ntohs(udp->dest);
    }

    // Update flow stats with TCP flags
    struct flow_stats *stats = bpf_map_lookup_elem(&flow_stats, &key);
    if (stats) {
        stats->flags_seen |= tcp_flags;

        // Emit event for new flows or interesting packets
        if (tcp_flags & (0x02 | 0x01 | 0x04)) {  // SYN, FIN, RST
            struct traffic_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
            if (event) {
                event->timestamp = bpf_ktime_get_ns();
                event->flow = key;
                event->len = skb->len;
                event->direction = direction;
                event->tcp_flags = tcp_flags;
                event->event_type = EVENT_PACKET;
                event->pid = 0;
                bpf_ringbuf_submit(event, 0);
            }
        }
    }

    return TC_ACT_OK;
}

SEC("tc/ingress")
int tc_ingress(struct __sk_buff *skb)
{
    return process_packet(skb, 0);
}

SEC("tc/egress")
int tc_egress(struct __sk_buff *skb)
{
    return process_packet(skb, 1);
}
```

## Step 4: Sock Ops Program

Create `sock_tracker.bpf.c`:

```c
// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "traffic_monitor.h"

char LICENSE[] SEC("license") = "GPL";

// Reference shared maps
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} global_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, struct flow_key);
    __type(value, struct flow_stats);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_stats SEC(".maps");

// Events ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

static __always_inline void update_stat(__u32 key, __u64 delta)
{
    __u64 *val = bpf_map_lookup_elem(&global_stats, &key);
    if (val)
        __sync_fetch_and_add(val, delta);
}

static __always_inline void extract_flow_key(struct bpf_sock_ops *skops,
                                              struct flow_key *key)
{
    key->src_ip = skops->local_ip4;
    key->dst_ip = skops->remote_ip4;
    key->src_port = skops->local_port;
    key->dst_port = bpf_ntohl(skops->remote_port) >> 16;
    key->protocol = IPPROTO_TCP;
}

SEC("sockops")
int sock_tracker(struct bpf_sock_ops *skops)
{
    if (skops->family != AF_INET)
        return 0;

    struct flow_key key;
    extract_flow_key(skops, &key);

    switch (skops->op) {
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: {
        // Update flow state
        struct flow_stats *stats = bpf_map_lookup_elem(&flow_stats, &key);
        if (stats) {
            stats->state = 1;  // ESTABLISHED
        }

        // Enable RTT tracking
        bpf_sock_ops_cb_flags_set(skops,
            skops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_RTT_CB_FLAG);

        update_stat(STAT_CONNECTIONS, 1);

        // Emit event
        struct traffic_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
        if (event) {
            event->timestamp = bpf_ktime_get_ns();
            event->flow = key;
            event->event_type = EVENT_CONNECTION;
            event->pid = bpf_get_current_pid_tgid() >> 32;
            bpf_get_current_comm(&event->comm, sizeof(event->comm));
            bpf_ringbuf_submit(event, 0);
        }
        break;
    }

    case BPF_SOCK_OPS_RTT_CB: {
        __u32 rtt = skops->srtt_us >> 3;

        struct flow_stats *stats = bpf_map_lookup_elem(&flow_stats, &key);
        if (stats) {
            // Update rolling average
            stats->avg_rtt = (stats->avg_rtt * 7 + rtt) / 8;
        }
        break;
    }

    case BPF_SOCK_OPS_STATE_CB: {
        int new_state = skops->args[1];
        if (new_state == 7) {  // TCP_CLOSE
            struct flow_stats *stats = bpf_map_lookup_elem(&flow_stats, &key);
            if (stats) {
                stats->state = 0;  // CLOSED
            }

            struct traffic_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
            if (event) {
                event->timestamp = bpf_ktime_get_ns();
                event->flow = key;
                event->event_type = EVENT_FLOW_END;
                event->pid = bpf_get_current_pid_tgid() >> 32;
                bpf_get_current_comm(&event->comm, sizeof(event->comm));
                bpf_ringbuf_submit(event, 0);
            }
        }
        break;
    }
    }

    return 0;
}
```

## Step 5: Userspace Monitor

Create `traffic_monitor.c`:

```c
// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <time.h>

#include "traffic_monitor.h"
#include "xdp_stats.skel.h"
#include "tc_parser.skel.h"
#include "sock_tracker.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

static const char *ip_str(__u32 addr)
{
    static char buf[4][16];
    static int idx = 0;
    idx = (idx + 1) % 4;
    struct in_addr in = {.s_addr = addr};
    inet_ntop(AF_INET, &in, buf[idx], sizeof(buf[idx]));
    return buf[idx];
}

static const char *proto_str(__u8 proto)
{
    switch (proto) {
    case IPPROTO_TCP: return "TCP";
    case IPPROTO_UDP: return "UDP";
    case IPPROTO_ICMP: return "ICMP";
    default: return "???";
    }
}

static const char *format_bytes(__u64 bytes)
{
    static char buf[32];
    if (bytes >= 1000000000)
        snprintf(buf, sizeof(buf), "%.1fG", bytes / 1e9);
    else if (bytes >= 1000000)
        snprintf(buf, sizeof(buf), "%.1fM", bytes / 1e6);
    else if (bytes >= 1000)
        snprintf(buf, sizeof(buf), "%.1fK", bytes / 1e3);
    else
        snprintf(buf, sizeof(buf), "%lluB", bytes);
    return buf;
}

static void print_dashboard(int global_stats_fd, int flow_stats_fd)
{
    __u64 stats[STAT_MAX] = {};

    // Read global stats
    for (int i = 0; i < STAT_MAX; i++) {
        __u64 values[256];  // Assuming max 256 CPUs
        if (bpf_map_lookup_elem(global_stats_fd, &i, values) == 0) {
            for (int cpu = 0; cpu < 256; cpu++)
                stats[i] += values[cpu];
        }
    }

    printf("\033[2J\033[H");  // Clear screen
    printf("╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║                    Traffic Monitor Dashboard                      ║\n");
    printf("╠══════════════════════════════════════════════════════════════════╣\n");

    // Global stats
    printf("║ RX: %10s pkts %10s   TX: %10s pkts %10s ║\n",
           format_bytes(stats[STAT_RX_PACKETS]), format_bytes(stats[STAT_RX_BYTES]),
           format_bytes(stats[STAT_TX_PACKETS]), format_bytes(stats[STAT_TX_BYTES]));
    printf("║ TCP: %9s   UDP: %9s   ICMP: %8s   Other: %6s ║\n",
           format_bytes(stats[STAT_TCP_PACKETS]),
           format_bytes(stats[STAT_UDP_PACKETS]),
           format_bytes(stats[STAT_ICMP_PACKETS]),
           format_bytes(stats[STAT_OTHER_PACKETS]));
    printf("║ Active connections: %-10llu                                    ║\n",
           stats[STAT_CONNECTIONS]);

    printf("╠══════════════════════════════════════════════════════════════════╣\n");
    printf("║                         Top Flows                                 ║\n");
    printf("╠══════════════════════════════════════════════════════════════════╣\n");

    // Top flows
    struct flow_key key, next_key;
    struct flow_stats flow;
    struct {
        struct flow_key key;
        struct flow_stats stats;
    } top_flows[10];
    int flow_count = 0;

    memset(&key, 0, sizeof(key));
    while (bpf_map_get_next_key(flow_stats_fd, &key, &next_key) == 0 && flow_count < 10) {
        if (bpf_map_lookup_elem(flow_stats_fd, &next_key, &flow) == 0) {
            // Simple insertion sort by packets
            int i;
            for (i = flow_count - 1; i >= 0 && top_flows[i].stats.packets < flow.packets; i--) {
                if (i + 1 < 10)
                    top_flows[i + 1] = top_flows[i];
            }
            if (i + 1 < 10) {
                top_flows[i + 1].key = next_key;
                top_flows[i + 1].stats = flow;
                if (flow_count < 10)
                    flow_count++;
            }
        }
        key = next_key;
    }

    printf("║ %-5s %-15s %-6s %-15s %-6s %8s %8s ║\n",
           "Proto", "Source", "Port", "Dest", "Port", "Packets", "Bytes");
    for (int i = 0; i < flow_count && i < 5; i++) {
        printf("║ %-5s %-15s %-6d %-15s %-6d %8s %8s ║\n",
               proto_str(top_flows[i].key.protocol),
               ip_str(top_flows[i].key.src_ip),
               top_flows[i].key.src_port,
               ip_str(top_flows[i].key.dst_ip),
               top_flows[i].key.dst_port,
               format_bytes(top_flows[i].stats.packets),
               format_bytes(top_flows[i].stats.bytes));
    }

    printf("╚══════════════════════════════════════════════════════════════════╝\n");
    printf("Press Ctrl+C to exit\n");
}

int main(int argc, char **argv)
{
    struct xdp_stats_bpf *xdp_skel = NULL;
    struct tc_parser_bpf *tc_skel = NULL;
    struct sock_tracker_bpf *sock_skel = NULL;
    const char *interface = "eth0";
    const char *cgroup_path = "/sys/fs/cgroup";
    int ifindex;
    int cgroup_fd = -1;
    int opt;

    while ((opt = getopt(argc, argv, "i:c:h")) != -1) {
        switch (opt) {
        case 'i':
            interface = optarg;
            break;
        case 'c':
            cgroup_path = optarg;
            break;
        case 'h':
        default:
            fprintf(stderr, "Usage: %s [-i interface] [-c cgroup]\n", argv[0]);
            return opt == 'h' ? 0 : 1;
        }
    }

    ifindex = if_nametoindex(interface);
    if (!ifindex) {
        fprintf(stderr, "Interface %s not found\n", interface);
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Create pin directory
    system("mkdir -p /sys/fs/bpf/traffic_monitor");

    // Load XDP program
    xdp_skel = xdp_stats_bpf__open_and_load();
    if (!xdp_skel) {
        fprintf(stderr, "Failed to load XDP program\n");
        return 1;
    }

    // Attach XDP
    if (bpf_xdp_attach(ifindex, bpf_program__fd(xdp_skel->progs.xdp_stats),
                       XDP_FLAGS_SKB_MODE, NULL) < 0) {
        fprintf(stderr, "Failed to attach XDP\n");
        goto cleanup;
    }

    // Load and attach TC programs
    tc_skel = tc_parser_bpf__open_and_load();
    if (!tc_skel) {
        fprintf(stderr, "Failed to load TC program\n");
        goto cleanup;
    }

    LIBBPF_OPTS(bpf_tc_hook, hook_in, .ifindex = ifindex, .attach_point = BPF_TC_INGRESS);
    LIBBPF_OPTS(bpf_tc_hook, hook_out, .ifindex = ifindex, .attach_point = BPF_TC_EGRESS);
    LIBBPF_OPTS(bpf_tc_opts, tc_opts_in, .prog_fd = bpf_program__fd(tc_skel->progs.tc_ingress));
    LIBBPF_OPTS(bpf_tc_opts, tc_opts_out, .prog_fd = bpf_program__fd(tc_skel->progs.tc_egress));

    bpf_tc_hook_create(&hook_in);
    bpf_tc_hook_create(&hook_out);
    bpf_tc_attach(&hook_in, &tc_opts_in);
    bpf_tc_attach(&hook_out, &tc_opts_out);

    // Load and attach sock_ops
    sock_skel = sock_tracker_bpf__open_and_load();
    if (!sock_skel) {
        fprintf(stderr, "Failed to load sock_ops program\n");
        goto cleanup;
    }

    cgroup_fd = open(cgroup_path, O_DIRECTORY | O_RDONLY);
    if (cgroup_fd >= 0) {
        bpf_prog_attach(bpf_program__fd(sock_skel->progs.sock_tracker),
                        cgroup_fd, BPF_CGROUP_SOCK_OPS, 0);
    }

    printf("Traffic Monitor started on %s\n", interface);

    // Main loop - dashboard mode
    while (!exiting) {
        print_dashboard(
            bpf_map__fd(xdp_skel->maps.global_stats),
            bpf_map__fd(xdp_skel->maps.flow_stats)
        );
        sleep(1);
    }

cleanup:
    if (cgroup_fd >= 0) {
        bpf_prog_detach(cgroup_fd, BPF_CGROUP_SOCK_OPS);
        close(cgroup_fd);
    }

    if (tc_skel) {
        bpf_tc_hook_destroy(&hook_in);
        bpf_tc_hook_destroy(&hook_out);
    }

    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);

    sock_tracker_bpf__destroy(sock_skel);
    tc_parser_bpf__destroy(tc_skel);
    xdp_stats_bpf__destroy(xdp_skel);

    printf("\nCleaned up\n");
    return 0;
}
```

## Step 6: Makefile

```makefile
CLANG ?= clang
BPFTOOL ?= bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

CFLAGS := -g -O2 -Wall
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)

LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LDFLAGS := $(shell pkg-config --libs libbpf 2>/dev/null || echo "-lbpf -lelf -lz")

BPF_PROGS := xdp_stats tc_parser sock_tracker
SKELS := $(addsuffix .skel.h,$(BPF_PROGS))
BPF_OBJS := $(addsuffix .bpf.o,$(BPF_PROGS))

all: traffic_monitor

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

%.bpf.o: %.bpf.c traffic_monitor.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

%.skel.h: %.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

traffic_monitor: traffic_monitor.c $(SKELS) traffic_monitor.h
	$(CLANG) $(CFLAGS) $(LIBBPF_CFLAGS) $< $(LIBBPF_LDFLAGS) -o $@

clean:
	rm -f traffic_monitor *.bpf.o *.skel.h vmlinux.h
```

## Testing

```bash
# Build
make

# Run on eth0
sudo ./traffic_monitor -i eth0

# Generate some traffic
curl https://example.com &
ping -c 5 8.8.8.8 &
```

## Challenges

1. **Prometheus exporter**: Export metrics in Prometheus format.

2. **JSON API**: Add HTTP endpoint for querying stats.

3. **Historical data**: Store and query historical flow data.

4. **Alerts**: Add threshold-based alerting.

5. **Multi-interface**: Monitor multiple interfaces.

## What's Next

In [Project 08: Proxy Redirect](../project08-proxy-redirect/index.md), you'll build the capstone project — a transparent proxy using cgroup hooks.
