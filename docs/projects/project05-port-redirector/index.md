# Project 05: Port Redirector

Build a port redirector that rewrites destination ports in packets. This project teaches packet modification, checksum recalculation, and bidirectional traffic handling — essential skills for building load balancers and NAT systems.

## What You'll Build

A tool that:

- Redirects traffic from one port to another
- Handles both directions (request and response)
- Correctly recalculates IP and TCP/UDP checksums
- Uses connection tracking for stateful redirection

## Learning Objectives

- Modify packet headers in eBPF
- Calculate L3 and L4 checksums incrementally
- Track connections with BPF maps
- Handle bidirectional traffic flows

## Prerequisites

- Projects 1-4
- Ch 23: Header Rewriting

## Architecture

```
Client requests port 8080         Server listens on port 80
       │                                   │
       ▼                                   ▼
┌─────────────────────────────────────────────────┐
│                TC Ingress                        │
│  Client → Server: rewrite dst port 8080 → 80    │
│  Record in conntrack map                         │
└─────────────────────────────────────────────────┘
                      │
                      ▼
              Server receives on :80
                      │
                      ▼
┌─────────────────────────────────────────────────┐
│                TC Egress                         │
│  Server → Client: rewrite src port 80 → 8080    │
│  Lookup conntrack map for reverse translation    │
└─────────────────────────────────────────────────┘
                      │
                      ▼
         Client sees response from :8080
```

## Project Structure

```
port_redirector/
├── Makefile
├── port_redirector.bpf.c
├── port_redirector.h
└── port_redirector.c
```

## Step 1: Shared Header

Create `port_redirector.h`:

```c
#ifndef __PORT_REDIRECTOR_H
#define __PORT_REDIRECTOR_H

// Connection tracking key
struct conn_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
};

// Connection tracking value
struct conn_val {
    __u16 orig_port;    // Original port before translation
    __u64 last_seen;    // Timestamp for cleanup
    __u64 packets;      // Packet count
    __u64 bytes;        // Byte count
};

// Redirect configuration
struct redirect_config {
    __u16 from_port;    // Port to intercept
    __u16 to_port;      // Port to redirect to
    __u8 enabled;
};

// Statistics event
struct stats_event {
    __u64 timestamp;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 direction;     // 0 = ingress, 1 = egress
    __u8 action;        // 0 = pass, 1 = redirected
};

#endif
```

## Step 2: BPF Program

Create `port_redirector.bpf.c`:

```c
// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "port_redirector.h"

char LICENSE[] SEC("license") = "GPL";

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

// Configuration
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct redirect_config);
} config SEC(".maps");

// Connection tracking
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct conn_key);
    __type(value, struct conn_val);
} conntrack SEC(".maps");

// Statistics
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Counters
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

#define STAT_PACKETS   0
#define STAT_BYTES     1
#define STAT_REDIRECTS 2
#define STAT_CONNTRACK 3

static __always_inline void update_stat(__u32 key, __u64 val)
{
    __u64 *stat = bpf_map_lookup_elem(&stats, &key);
    if (stat)
        __sync_fetch_and_add(stat, val);
}

// Incremental checksum update for port change
static __always_inline void update_csum(__u16 *csum, __u16 old_val, __u16 new_val)
{
    __u32 sum = ~(*csum) & 0xFFFF;
    sum += (~old_val & 0xFFFF) + new_val;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += sum >> 16;
    *csum = ~sum;
}

SEC("tc/ingress")
int tc_ingress(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // Get config
    __u32 cfg_key = 0;
    struct redirect_config *cfg = bpf_map_lookup_elem(&config, &cfg_key);
    if (!cfg || !cfg->enabled)
        return TC_ACT_OK;

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

    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;

    // Parse transport
    int ip_hdr_len = ip->ihl * 4;
    void *transport = (void *)ip + ip_hdr_len;

    __u16 src_port, dst_port;
    __u16 *dst_port_ptr;
    __u16 *csum_ptr;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = transport;
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;

        src_port = bpf_ntohs(tcp->source);
        dst_port = bpf_ntohs(tcp->dest);
        dst_port_ptr = &tcp->dest;
        csum_ptr = &tcp->check;
    } else {
        struct udphdr *udp = transport;
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;

        src_port = bpf_ntohs(udp->source);
        dst_port = bpf_ntohs(udp->dest);
        dst_port_ptr = &udp->dest;
        csum_ptr = &udp->check;
    }

    update_stat(STAT_PACKETS, 1);
    update_stat(STAT_BYTES, skb->len);

    // Check if this packet needs redirection
    if (dst_port != cfg->from_port)
        return TC_ACT_OK;

    // Create connection tracking entry
    struct conn_key key = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .src_port = src_port,
        .dst_port = cfg->to_port,  // Track with translated port
        .protocol = ip->protocol,
    };

    struct conn_val val = {
        .orig_port = cfg->from_port,
        .last_seen = bpf_ktime_get_ns(),
        .packets = 1,
        .bytes = skb->len,
    };

    bpf_map_update_elem(&conntrack, &key, &val, BPF_ANY);
    update_stat(STAT_CONNTRACK, 1);

    // Rewrite destination port
    __u16 old_port = *dst_port_ptr;
    __u16 new_port = bpf_htons(cfg->to_port);

    // Update checksum
    update_csum(csum_ptr, old_port, new_port);

    // Rewrite port
    *dst_port_ptr = new_port;

    update_stat(STAT_REDIRECTS, 1);

    // Log event
    struct stats_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (event) {
        event->timestamp = bpf_ktime_get_ns();
        event->src_ip = ip->saddr;
        event->dst_ip = ip->daddr;
        event->src_port = src_port;
        event->dst_port = cfg->to_port;
        event->direction = 0;  // ingress
        event->action = 1;     // redirected
        bpf_ringbuf_submit(event, 0);
    }

    return TC_ACT_OK;
}

SEC("tc/egress")
int tc_egress(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // Get config
    __u32 cfg_key = 0;
    struct redirect_config *cfg = bpf_map_lookup_elem(&config, &cfg_key);
    if (!cfg || !cfg->enabled)
        return TC_ACT_OK;

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

    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;

    // Parse transport
    int ip_hdr_len = ip->ihl * 4;
    void *transport = (void *)ip + ip_hdr_len;

    __u16 src_port, dst_port;
    __u16 *src_port_ptr;
    __u16 *csum_ptr;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = transport;
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;

        src_port = bpf_ntohs(tcp->source);
        dst_port = bpf_ntohs(tcp->dest);
        src_port_ptr = &tcp->source;
        csum_ptr = &tcp->check;
    } else {
        struct udphdr *udp = transport;
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;

        src_port = bpf_ntohs(udp->source);
        dst_port = bpf_ntohs(udp->dest);
        src_port_ptr = &udp->source;
        csum_ptr = &udp->check;
    }

    // Check if this is a response to a redirected connection
    if (src_port != cfg->to_port)
        return TC_ACT_OK;

    // Look up reverse connection
    struct conn_key key = {
        .src_ip = ip->daddr,      // Original client
        .dst_ip = ip->saddr,      // Server
        .src_port = dst_port,     // Original client port
        .dst_port = src_port,     // Server port (to_port)
        .protocol = ip->protocol,
    };

    struct conn_val *val = bpf_map_lookup_elem(&conntrack, &key);
    if (!val)
        return TC_ACT_OK;

    // Update stats
    val->last_seen = bpf_ktime_get_ns();
    val->packets++;
    val->bytes += skb->len;

    // Rewrite source port back to original
    __u16 old_port = *src_port_ptr;
    __u16 new_port = bpf_htons(val->orig_port);

    update_csum(csum_ptr, old_port, new_port);
    *src_port_ptr = new_port;

    update_stat(STAT_REDIRECTS, 1);

    // Log event
    struct stats_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (event) {
        event->timestamp = bpf_ktime_get_ns();
        event->src_ip = ip->saddr;
        event->dst_ip = ip->daddr;
        event->src_port = val->orig_port;
        event->dst_port = dst_port;
        event->direction = 1;  // egress
        event->action = 1;     // redirected
        bpf_ringbuf_submit(event, 0);
    }

    return TC_ACT_OK;
}
```

## Step 3: Userspace Program

Create `port_redirector.c`:

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

#include "port_redirector.h"
#include "port_redirector.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

static const char *ip_str(__u32 addr)
{
    static char buf[16];
    struct in_addr in = {.s_addr = addr};
    inet_ntop(AF_INET, &in, buf, sizeof(buf));
    return buf;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct stats_event *event = data;

    printf("%s %s:%d -> %s:%d [%s]\n",
           event->direction ? "EGRESS " : "INGRESS",
           ip_str(event->src_ip), event->src_port,
           ip_str(event->dst_ip), event->dst_port,
           event->action ? "REDIRECTED" : "PASS");

    return 0;
}

static int attach_tc(int prog_fd, int ifindex, bool ingress)
{
    LIBBPF_OPTS(bpf_tc_hook, hook,
        .ifindex = ifindex,
        .attach_point = ingress ? BPF_TC_INGRESS : BPF_TC_EGRESS,
    );

    LIBBPF_OPTS(bpf_tc_opts, opts,
        .prog_fd = prog_fd,
    );

    int err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST)
        return err;

    return bpf_tc_attach(&hook, &opts);
}

static void detach_tc(int ifindex)
{
    LIBBPF_OPTS(bpf_tc_hook, hook_in,
        .ifindex = ifindex,
        .attach_point = BPF_TC_INGRESS,
    );
    LIBBPF_OPTS(bpf_tc_hook, hook_out,
        .ifindex = ifindex,
        .attach_point = BPF_TC_EGRESS,
    );

    bpf_tc_hook_destroy(&hook_in);
    bpf_tc_hook_destroy(&hook_out);
}

static void print_stats(struct port_redirector_bpf *skel)
{
    __u32 key;
    __u64 value;

    printf("\n=== Statistics ===\n");

    key = 0;  // STAT_PACKETS
    bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats), &key, &value);
    printf("Packets processed: %llu\n", value);

    key = 1;  // STAT_BYTES
    bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats), &key, &value);
    printf("Bytes processed: %llu\n", value);

    key = 2;  // STAT_REDIRECTS
    bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats), &key, &value);
    printf("Redirections: %llu\n", value);

    key = 3;  // STAT_CONNTRACK
    bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats), &key, &value);
    printf("Connections tracked: %llu\n", value);
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s -i <interface> -f <from_port> -t <to_port> [-v]\n", prog);
    fprintf(stderr, "\nExample: %s -i eth0 -f 8080 -t 80\n", prog);
    fprintf(stderr, "  Redirects traffic destined for port 8080 to port 80\n");
}

int main(int argc, char **argv)
{
    struct port_redirector_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    char *interface = NULL;
    __u16 from_port = 0;
    __u16 to_port = 0;
    bool verbose = false;
    int opt;

    while ((opt = getopt(argc, argv, "i:f:t:vh")) != -1) {
        switch (opt) {
        case 'i':
            interface = optarg;
            break;
        case 'f':
            from_port = atoi(optarg);
            break;
        case 't':
            to_port = atoi(optarg);
            break;
        case 'v':
            verbose = true;
            break;
        case 'h':
        default:
            usage(argv[0]);
            return opt == 'h' ? 0 : 1;
        }
    }

    if (!interface || !from_port || !to_port) {
        usage(argv[0]);
        return 1;
    }

    int ifindex = if_nametoindex(interface);
    if (!ifindex) {
        fprintf(stderr, "Interface %s not found\n", interface);
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Load BPF
    skel = port_redirector_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load BPF\n");
        return 1;
    }

    // Configure redirection
    __u32 key = 0;
    struct redirect_config cfg = {
        .from_port = from_port,
        .to_port = to_port,
        .enabled = 1,
    };
    bpf_map_update_elem(bpf_map__fd(skel->maps.config), &key, &cfg, 0);

    // Attach TC
    if (attach_tc(bpf_program__fd(skel->progs.tc_ingress), ifindex, true)) {
        fprintf(stderr, "Failed to attach ingress\n");
        goto cleanup;
    }

    if (attach_tc(bpf_program__fd(skel->progs.tc_egress), ifindex, false)) {
        fprintf(stderr, "Failed to attach egress\n");
        goto cleanup;
    }

    printf("Port Redirector started on %s\n", interface);
    printf("Redirecting: port %d -> port %d\n", from_port, to_port);
    printf("Press Ctrl+C to stop\n\n");

    // Set up ring buffer for verbose mode
    if (verbose) {
        rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    }

    while (!exiting) {
        if (verbose && rb) {
            ring_buffer__poll(rb, 100);
        } else {
            sleep(1);
        }
    }

    print_stats(skel);

cleanup:
    ring_buffer__free(rb);
    detach_tc(ifindex);
    port_redirector_bpf__destroy(skel);

    printf("\nCleaned up\n");
    return 0;
}
```

## Step 4: Makefile

Create `Makefile`:

```makefile
CLANG ?= clang
BPFTOOL ?= bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

CFLAGS := -g -O2 -Wall
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)

LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LDFLAGS := $(shell pkg-config --libs libbpf 2>/dev/null || echo "-lbpf -lelf -lz")

all: port_redirector

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

port_redirector.bpf.o: port_redirector.bpf.c port_redirector.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

port_redirector.skel.h: port_redirector.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

port_redirector: port_redirector.c port_redirector.skel.h port_redirector.h
	$(CLANG) $(CFLAGS) $(LIBBPF_CFLAGS) $< $(LIBBPF_LDFLAGS) -o $@

clean:
	rm -f port_redirector *.o *.skel.h vmlinux.h
```

## Testing

```bash
# Build
make

# Start a web server on port 80
python3 -m http.server 80 &

# Redirect port 8080 to 80
sudo ./port_redirector -i lo -f 8080 -t 80 -v

# In another terminal, test the redirection
curl http://localhost:8080/
# Should get response from server on port 80!
```

## How It Works

1. **Ingress (Client → Server)**:
   - Client sends packet to port 8080
   - TC ingress hook intercepts
   - Creates conntrack entry
   - Rewrites dst port: 8080 → 80
   - Updates checksum
   - Server receives on port 80

2. **Egress (Server → Client)**:
   - Server responds from port 80
   - TC egress hook intercepts
   - Looks up conntrack entry
   - Rewrites src port: 80 → 8080
   - Updates checksum
   - Client sees response from port 8080

## Challenges

1. **UDP support**: Test with UDP traffic (nc -u).

2. **Multiple redirects**: Support multiple port mappings.

3. **IP DNAT**: Also rewrite IP addresses (full NAT).

4. **Connection cleanup**: Implement timeout-based cleanup.

5. **Statistics per connection**: Track bytes/packets per flow.

## What's Next

In [Project 06: Connection Tracker](../project06-connection-tracker/index.md), you'll build a full connection tracker using sock_ops programs.
