# Project 04: Header Inspector

Build a Traffic Control (TC) based packet inspector using libbpf. This project marks your transition from BCC (Python) to the production-grade libbpf toolchain with CO-RE (Compile Once, Run Everywhere).

## What You'll Build

A tool that:

- Inspects all packets using TC hooks
- Displays Ethernet, IP, TCP/UDP header fields
- Filters by protocol, port, or IP
- Uses the libbpf skeleton workflow

## Learning Objectives

- Set up libbpf development environment
- Use bpftool to generate skeleton headers
- Write TC BPF programs
- Parse all protocol layers safely
- Handle ring buffer events in C

## Prerequisites

- Part 1 & 2: C and eBPF Fundamentals
- Ch 16: libbpf & CO-RE
- Ch 20: TC Programs
- Ch 22: Packet Parsing

## Project Structure

```
header_inspector/
├── Makefile
├── header_inspector.bpf.c    # eBPF program
├── header_inspector.h        # Shared structures
└── header_inspector.c        # Userspace program
```

## Step 1: Shared Header

Create `header_inspector.h`:

```c
#ifndef __HEADER_INSPECTOR_H
#define __HEADER_INSPECTOR_H

#define MAX_PAYLOAD_SIZE 64

struct packet_event {
    __u64 timestamp;
    __u32 len;
    __u32 ifindex;

    // Ethernet
    __u8 eth_src[6];
    __u8 eth_dst[6];
    __u16 eth_proto;

    // IP
    __u8 ip_version;
    __u8 ip_protocol;
    __u8 ip_ttl;
    __u32 ip_src;
    __u32 ip_dst;

    // TCP/UDP
    __u16 src_port;
    __u16 dst_port;

    // TCP flags
    __u8 tcp_flags;

    // Direction
    __u8 ingress;

    // Payload sample
    __u8 payload[MAX_PAYLOAD_SIZE];
    __u32 payload_len;
};

#endif /* __HEADER_INSPECTOR_H */
```

## Step 2: BPF Program

Create `header_inspector.bpf.c`:

```c
// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "header_inspector.h"

char LICENSE[] SEC("license") = "GPL";

// Ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Configuration map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct {
        __u8 enabled;
        __u8 filter_proto;     // 0 = all, 6 = TCP, 17 = UDP
        __u16 filter_port;     // 0 = all
    });
} config SEC(".maps");

// Protocol numbers
#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1

// TCP flags
#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20

static __always_inline int parse_packet(struct __sk_buff *skb, __u8 ingress)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    // Only handle IPv4 for now
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    // Check filter
    __u32 cfg_key = 0;
    struct {
        __u8 enabled;
        __u8 filter_proto;
        __u16 filter_port;
    } *cfg = bpf_map_lookup_elem(&config, &cfg_key);

    if (cfg && !cfg->enabled)
        return TC_ACT_OK;

    if (cfg && cfg->filter_proto && ip->protocol != cfg->filter_proto)
        return TC_ACT_OK;

    // Reserve event
    struct packet_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return TC_ACT_OK;

    // Fill common fields
    event->timestamp = bpf_ktime_get_ns();
    event->len = skb->len;
    event->ifindex = skb->ifindex;
    event->ingress = ingress;

    // Ethernet
    __builtin_memcpy(event->eth_src, eth->h_source, 6);
    __builtin_memcpy(event->eth_dst, eth->h_dest, 6);
    event->eth_proto = bpf_ntohs(eth->h_proto);

    // IP
    event->ip_version = ip->version;
    event->ip_protocol = ip->protocol;
    event->ip_ttl = ip->ttl;
    event->ip_src = ip->saddr;
    event->ip_dst = ip->daddr;

    // Transport layer
    int ip_hdr_len = ip->ihl * 4;
    void *transport = (void *)ip + ip_hdr_len;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = transport;
        if ((void *)(tcp + 1) > data_end) {
            bpf_ringbuf_discard(event, 0);
            return TC_ACT_OK;
        }

        event->src_port = bpf_ntohs(tcp->source);
        event->dst_port = bpf_ntohs(tcp->dest);

        // TCP flags
        event->tcp_flags = 0;
        if (tcp->fin) event->tcp_flags |= TCP_FIN;
        if (tcp->syn) event->tcp_flags |= TCP_SYN;
        if (tcp->rst) event->tcp_flags |= TCP_RST;
        if (tcp->psh) event->tcp_flags |= TCP_PSH;
        if (tcp->ack) event->tcp_flags |= TCP_ACK;
        if (tcp->urg) event->tcp_flags |= TCP_URG;

        // Port filter
        if (cfg && cfg->filter_port &&
            event->src_port != cfg->filter_port &&
            event->dst_port != cfg->filter_port) {
            bpf_ringbuf_discard(event, 0);
            return TC_ACT_OK;
        }

        // Copy payload sample
        int tcp_hdr_len = tcp->doff * 4;
        void *payload = (void *)tcp + tcp_hdr_len;
        int payload_size = data_end - payload;
        if (payload_size > 0) {
            int copy_size = payload_size < MAX_PAYLOAD_SIZE ? payload_size : MAX_PAYLOAD_SIZE;
            if (payload + copy_size <= data_end) {
                bpf_probe_read_kernel(event->payload, copy_size, payload);
                event->payload_len = copy_size;
            }
        }

    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = transport;
        if ((void *)(udp + 1) > data_end) {
            bpf_ringbuf_discard(event, 0);
            return TC_ACT_OK;
        }

        event->src_port = bpf_ntohs(udp->source);
        event->dst_port = bpf_ntohs(udp->dest);
        event->tcp_flags = 0;

        // Port filter
        if (cfg && cfg->filter_port &&
            event->src_port != cfg->filter_port &&
            event->dst_port != cfg->filter_port) {
            bpf_ringbuf_discard(event, 0);
            return TC_ACT_OK;
        }

        // Copy payload sample
        void *payload = (void *)(udp + 1);
        int payload_size = data_end - payload;
        if (payload_size > 0) {
            int copy_size = payload_size < MAX_PAYLOAD_SIZE ? payload_size : MAX_PAYLOAD_SIZE;
            if (payload + copy_size <= data_end) {
                bpf_probe_read_kernel(event->payload, copy_size, payload);
                event->payload_len = copy_size;
            }
        }

    } else {
        event->src_port = 0;
        event->dst_port = 0;
        event->tcp_flags = 0;
        event->payload_len = 0;
    }

    bpf_ringbuf_submit(event, 0);
    return TC_ACT_OK;
}

SEC("tc/ingress")
int tc_ingress(struct __sk_buff *skb)
{
    return parse_packet(skb, 1);
}

SEC("tc/egress")
int tc_egress(struct __sk_buff *skb)
{
    return parse_packet(skb, 0);
}
```

## Step 3: Userspace Program

Create `header_inspector.c`:

```c
// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "header_inspector.h"
#include "header_inspector.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

// TCP flag names
static const char *tcp_flags_str(__u8 flags)
{
    static char buf[32];
    buf[0] = '\0';

    if (flags & 0x02) strcat(buf, "S");  // SYN
    if (flags & 0x10) strcat(buf, "A");  // ACK
    if (flags & 0x01) strcat(buf, "F");  // FIN
    if (flags & 0x04) strcat(buf, "R");  // RST
    if (flags & 0x08) strcat(buf, "P");  // PSH
    if (flags & 0x20) strcat(buf, "U");  // URG

    return buf[0] ? buf : ".";
}

// MAC address formatter
static const char *mac_str(const __u8 *mac)
{
    static char buf[18];
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}

// IP address formatter
static const char *ip_str(__u32 addr)
{
    static char buf[16];
    struct in_addr in = {.s_addr = addr};
    inet_ntop(AF_INET, &in, buf, sizeof(buf));
    return buf;
}

// Protocol name
static const char *proto_str(__u8 proto)
{
    switch (proto) {
    case 6:  return "TCP";
    case 17: return "UDP";
    case 1:  return "ICMP";
    default: return "???";
    }
}

// Hexdump payload
static void hexdump(const __u8 *data, int len)
{
    if (len == 0) return;

    printf("    Payload (%d bytes): ", len);
    for (int i = 0; i < len && i < 32; i++) {
        printf("%02x ", data[i]);
    }
    if (len > 32) printf("...");
    printf("\n");

    // ASCII representation
    printf("    ASCII: ");
    for (int i = 0; i < len && i < 32; i++) {
        char c = data[i];
        printf("%c", (c >= 32 && c < 127) ? c : '.');
    }
    printf("\n");
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct packet_event *event = data;
    char ifname[IF_NAMESIZE];

    if_indextoname(event->ifindex, ifname);

    printf("\n════════════════════════════════════════════════════════════════\n");
    printf("  %s on %s (%d bytes)\n",
           event->ingress ? "INGRESS" : "EGRESS",
           ifname, event->len);
    printf("════════════════════════════════════════════════════════════════\n");

    // Ethernet
    printf("  Ethernet:\n");
    printf("    Src: %s\n", mac_str(event->eth_src));
    printf("    Dst: %s\n", mac_str(event->eth_dst));
    printf("    Type: 0x%04x\n", event->eth_proto);

    // IP
    printf("  IPv%d:\n", event->ip_version);
    printf("    Src: %s\n", ip_str(event->ip_src));
    printf("    Dst: %s\n", ip_str(event->ip_dst));
    printf("    Proto: %s (%d)\n", proto_str(event->ip_protocol), event->ip_protocol);
    printf("    TTL: %d\n", event->ip_ttl);

    // Transport
    if (event->ip_protocol == 6) {  // TCP
        printf("  TCP:\n");
        printf("    %s:%d -> %s:%d\n",
               ip_str(event->ip_src), event->src_port,
               ip_str(event->ip_dst), event->dst_port);
        printf("    Flags: [%s]\n", tcp_flags_str(event->tcp_flags));
    } else if (event->ip_protocol == 17) {  // UDP
        printf("  UDP:\n");
        printf("    %s:%d -> %s:%d\n",
               ip_str(event->ip_src), event->src_port,
               ip_str(event->ip_dst), event->dst_port);
    }

    // Payload
    if (event->payload_len > 0) {
        hexdump(event->payload, event->payload_len);
    }

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
    if (err && err != -EEXIST) {
        fprintf(stderr, "Failed to create TC hook: %s\n", strerror(-err));
        return err;
    }

    err = bpf_tc_attach(&hook, &opts);
    if (err) {
        fprintf(stderr, "Failed to attach TC: %s\n", strerror(-err));
        return err;
    }

    return 0;
}

static void detach_tc(int ifindex, bool ingress)
{
    LIBBPF_OPTS(bpf_tc_hook, hook,
        .ifindex = ifindex,
        .attach_point = ingress ? BPF_TC_INGRESS : BPF_TC_EGRESS,
    );

    bpf_tc_hook_destroy(&hook);
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [-i interface] [-p protocol] [-P port]\n", prog);
    fprintf(stderr, "  -i interface   Network interface (default: eth0)\n");
    fprintf(stderr, "  -p protocol    Filter protocol: tcp, udp, or all (default: all)\n");
    fprintf(stderr, "  -P port        Filter port (default: all)\n");
}

int main(int argc, char **argv)
{
    struct header_inspector_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    char *interface = "eth0";
    __u8 filter_proto = 0;
    __u16 filter_port = 0;
    int opt;
    int err;

    // Parse arguments
    while ((opt = getopt(argc, argv, "i:p:P:h")) != -1) {
        switch (opt) {
        case 'i':
            interface = optarg;
            break;
        case 'p':
            if (strcmp(optarg, "tcp") == 0)
                filter_proto = 6;
            else if (strcmp(optarg, "udp") == 0)
                filter_proto = 17;
            else if (strcmp(optarg, "all") == 0)
                filter_proto = 0;
            else {
                fprintf(stderr, "Unknown protocol: %s\n", optarg);
                return 1;
            }
            break;
        case 'P':
            filter_port = atoi(optarg);
            break;
        case 'h':
        default:
            usage(argv[0]);
            return opt == 'h' ? 0 : 1;
        }
    }

    int ifindex = if_nametoindex(interface);
    if (!ifindex) {
        fprintf(stderr, "Interface %s not found\n", interface);
        return 1;
    }

    // Set up signal handler
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Open and load BPF program
    skel = header_inspector_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // Configure filter
    __u32 key = 0;
    struct {
        __u8 enabled;
        __u8 filter_proto;
        __u16 filter_port;
    } cfg = {
        .enabled = 1,
        .filter_proto = filter_proto,
        .filter_port = filter_port,
    };
    bpf_map_update_elem(bpf_map__fd(skel->maps.config), &key, &cfg, 0);

    // Attach TC programs
    err = attach_tc(bpf_program__fd(skel->progs.tc_ingress), ifindex, true);
    if (err)
        goto cleanup;

    err = attach_tc(bpf_program__fd(skel->progs.tc_egress), ifindex, false);
    if (err)
        goto cleanup;

    // Set up ring buffer
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("Header Inspector started on %s\n", interface);
    printf("Filter: proto=%s port=%d\n",
           filter_proto == 6 ? "TCP" : filter_proto == 17 ? "UDP" : "all",
           filter_port);
    printf("Press Ctrl+C to exit\n");

    // Main loop
    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    detach_tc(ifindex, true);
    detach_tc(ifindex, false);
    header_inspector_bpf__destroy(skel);

    printf("\nDetached\n");
    return err != 0;
}
```

## Step 4: Makefile

Create `Makefile`:

```makefile
# Header Inspector Makefile
CLANG ?= clang
LLC ?= llc
BPFTOOL ?= bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

CFLAGS := -g -O2 -Wall
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)

LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null || echo "-I/usr/include")
LIBBPF_LDFLAGS := $(shell pkg-config --libs libbpf 2>/dev/null || echo "-lbpf -lelf -lz")

.PHONY: all clean

all: header_inspector

# Generate vmlinux.h if not present
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# Compile BPF program
header_inspector.bpf.o: header_inspector.bpf.c header_inspector.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Generate skeleton
header_inspector.skel.h: header_inspector.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# Compile userspace program
header_inspector: header_inspector.c header_inspector.skel.h header_inspector.h
	$(CLANG) $(CFLAGS) $(LIBBPF_CFLAGS) $< $(LIBBPF_LDFLAGS) -o $@

clean:
	rm -f header_inspector header_inspector.bpf.o header_inspector.skel.h vmlinux.h
```

## Step 5: Build and Run

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt install clang llvm libbpf-dev linux-tools-common bpftool

# Build
make

# Run
sudo ./header_inspector -i eth0

# Filter to TCP only
sudo ./header_inspector -i eth0 -p tcp

# Filter to port 443
sudo ./header_inspector -i eth0 -P 443
```

## Sample Output

```
════════════════════════════════════════════════════════════════
  EGRESS on eth0 (74 bytes)
════════════════════════════════════════════════════════════════
  Ethernet:
    Src: 00:15:5d:01:02:03
    Dst: 00:15:5d:04:05:06
    Type: 0x0800
  IPv4:
    Src: 192.168.1.100
    Dst: 142.250.185.78
    Proto: TCP (6)
    TTL: 64
  TCP:
    192.168.1.100:52134 -> 142.250.185.78:443
    Flags: [S]

════════════════════════════════════════════════════════════════
  INGRESS on eth0 (66 bytes)
════════════════════════════════════════════════════════════════
  Ethernet:
    Src: 00:15:5d:04:05:06
    Dst: 00:15:5d:01:02:03
    Type: 0x0800
  IPv4:
    Src: 142.250.185.78
    Dst: 192.168.1.100
    Proto: TCP (6)
    TTL: 117
  TCP:
    142.250.185.78:443 -> 192.168.1.100:52134
    Flags: [SA]
```

## Challenges

1. **IPv6 support**: Add parsing for IPv6 packets.

2. **JSON output**: Add `-j` flag for JSON-formatted output.

3. **VLAN handling**: Parse 802.1Q VLAN tags.

4. **Statistics**: Track packet counts per protocol/port.

5. **pcap export**: Write packets to pcap format.

## What's Next

In [Project 05: Port Redirector](../project05-port-redirector/index.md), you'll modify packets by rewriting ports and recalculating checksums.
