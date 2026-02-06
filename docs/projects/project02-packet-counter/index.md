# Project 02: Packet Counter

Build an XDP-based packet counter that counts packets by protocol. This project introduces high-performance packet processing at the earliest point in the network stack.

## What You'll Build

A tool that:

- Counts packets at wire speed using XDP
- Categorizes by protocol (TCP, UDP, ICMP, other)
- Provides real-time statistics
- Demonstrates BPF map usage for aggregation

## Learning Objectives

- Write and attach XDP programs
- Parse Ethernet and IP headers
- Use BPF maps for kernel-side aggregation
- Handle network byte order

## Prerequisites

- Part 1: C Fundamentals (Ch 1-9)
- Part 2: eBPF Fundamentals through Ch 15
- Ch 21: XDP Programs
- Ch 22: Packet Parsing

## Architecture

```
                    Network Interface
                           │
                           ▼
              ┌────────────────────────┐
              │     XDP Program        │
              │  - Parse eth header    │
              │  - Parse IP header     │
              │  - Increment counter   │
              │  - Return XDP_PASS     │
              └────────────────────────┘
                           │
              ┌────────────┴────────────┐
              │    BPF Map (counters)   │
              │  TCP:  12345            │
              │  UDP:   6789            │
              │  ICMP:   234            │
              │  Other:   56            │
              └────────────┬────────────┘
                           │
                           ▼
              ┌────────────────────────┐
              │   Python (BCC)         │
              │  - Read map every 1s   │
              │  - Display statistics  │
              └────────────────────────┘
```

## Step 1: Basic Packet Counter

Create `packet_counter.py`:

```python
#!/usr/bin/env python3
"""XDP Packet Counter - counts packets by protocol."""
from bcc import BPF
import time
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("interface", help="Network interface to attach to")
args = parser.parse_args()

bpf_text = r"""
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

// Protocol indices
#define PROTO_TCP  0
#define PROTO_UDP  1
#define PROTO_ICMP 2
#define PROTO_OTHER 3

BPF_ARRAY(counters, u64, 4);

int xdp_count(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Only process IPv4
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Determine protocol
    u32 idx;
    switch (ip->protocol) {
        case IPPROTO_TCP:
            idx = PROTO_TCP;
            break;
        case IPPROTO_UDP:
            idx = PROTO_UDP;
            break;
        case IPPROTO_ICMP:
            idx = PROTO_ICMP;
            break;
        default:
            idx = PROTO_OTHER;
    }

    // Increment counter
    u64 *count = counters.lookup(&idx);
    if (count)
        (*count)++;

    return XDP_PASS;
}
"""

b = BPF(text=bpf_text)
fn = b.load_func("xdp_count", BPF.XDP)

# Attach to interface
b.attach_xdp(args.interface, fn, 0)

print(f"Counting packets on {args.interface}... Ctrl+C to stop")

protocol_names = ["TCP", "UDP", "ICMP", "Other"]

try:
    while True:
        time.sleep(1)
        print("\033[2J\033[H")  # Clear screen
        print(f"Packet Counter - {args.interface}")
        print("-" * 30)
        
        for i, name in enumerate(protocol_names):
            count = b["counters"][i].value
            print(f"{name:10s}: {count:>15,}")
            
except KeyboardInterrupt:
    pass
finally:
    b.remove_xdp(args.interface, 0)
    print("\nDetached")
```

Run:

```bash
sudo python3 packet_counter.py eth0
```

## Step 2: Add Per-Second Rates

```python
#!/usr/bin/env python3
"""Packet counter with rates."""
from bcc import BPF
import time
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("interface", help="Network interface")
args = parser.parse_args()

bpf_text = r"""
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#define PROTO_TCP   0
#define PROTO_UDP   1
#define PROTO_ICMP  2
#define PROTO_OTHER 3

BPF_ARRAY(counters, u64, 4);
BPF_ARRAY(bytes, u64, 4);

int xdp_count(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    u64 pkt_len = data_end - data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    u32 idx;
    switch (ip->protocol) {
        case IPPROTO_TCP:  idx = PROTO_TCP; break;
        case IPPROTO_UDP:  idx = PROTO_UDP; break;
        case IPPROTO_ICMP: idx = PROTO_ICMP; break;
        default: idx = PROTO_OTHER;
    }

    u64 *count = counters.lookup(&idx);
    if (count) (*count)++;

    u64 *byte_count = bytes.lookup(&idx);
    if (byte_count) (*byte_count) += pkt_len;

    return XDP_PASS;
}
"""

b = BPF(text=bpf_text)
fn = b.load_func("xdp_count", BPF.XDP)
b.attach_xdp(args.interface, fn, 0)

protocol_names = ["TCP", "UDP", "ICMP", "Other"]
prev_counts = [0, 0, 0, 0]
prev_bytes = [0, 0, 0, 0]

def format_bytes(b):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} TB"

try:
    while True:
        time.sleep(1)
        print("\033[2J\033[H")
        print(f"Packet Counter - {args.interface}")
        print(f"{'Protocol':<10} {'Packets':>15} {'pps':>12} {'Bytes':>12} {'bps':>12}")
        print("-" * 65)
        
        for i, name in enumerate(protocol_names):
            count = b["counters"][i].value
            byte_count = b["bytes"][i].value
            
            pps = count - prev_counts[i]
            bps = byte_count - prev_bytes[i]
            
            print(f"{name:<10} {count:>15,} {pps:>12,} {format_bytes(byte_count):>12} {format_bytes(bps):>10}/s")
            
            prev_counts[i] = count
            prev_bytes[i] = byte_count

except KeyboardInterrupt:
    pass
finally:
    b.remove_xdp(args.interface, 0)
```

## Step 3: Track Source IPs

```python
#!/usr/bin/env python3
"""Packet counter with source IP tracking."""
from bcc import BPF
import time
import argparse
import socket
import struct

parser = argparse.ArgumentParser()
parser.add_argument("interface", help="Network interface")
parser.add_argument("-n", "--top", type=int, default=10, help="Top N IPs")
args = parser.parse_args()

bpf_text = r"""
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

BPF_HASH(ip_count, u32, u64, 10240);
BPF_HASH(ip_bytes, u32, u64, 10240);

int xdp_count(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    u64 pkt_len = data_end - data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    u32 src_ip = ip->saddr;

    u64 *count = ip_count.lookup_or_try_init(&src_ip, &(u64){0});
    if (count) (*count)++;

    u64 *bytes = ip_bytes.lookup_or_try_init(&src_ip, &(u64){0});
    if (bytes) (*bytes) += pkt_len;

    return XDP_PASS;
}
"""

b = BPF(text=bpf_text)
fn = b.load_func("xdp_count", BPF.XDP)
b.attach_xdp(args.interface, fn, 0)

def ip_to_str(ip_int):
    """Convert integer IP to string (network byte order)."""
    return socket.inet_ntoa(struct.pack("I", ip_int))

try:
    while True:
        time.sleep(1)
        print("\033[2J\033[H")
        print(f"Top {args.top} Source IPs - {args.interface}")
        print(f"{'IP Address':<20} {'Packets':>15} {'Bytes':>15}")
        print("-" * 55)
        
        # Get top IPs by packet count
        ip_counts = {}
        for k, v in b["ip_count"].items():
            ip_counts[k.value] = v.value
        
        sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
        
        for ip, count in sorted_ips[:args.top]:
            bytes_count = b["ip_bytes"][b["ip_count"].Key(ip)].value
            print(f"{ip_to_str(ip):<20} {count:>15,} {bytes_count:>15,}")

except KeyboardInterrupt:
    pass
finally:
    b.remove_xdp(args.interface, 0)
```

## Step 4: Add Port Statistics

```python
#!/usr/bin/env python3
"""Packet counter with port tracking."""
from bcc import BPF
import time
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("interface", help="Network interface")
args = parser.parse_args()

bpf_text = r"""
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

struct port_key {
    u8 protocol;  // TCP or UDP
    u16 port;
};

BPF_HASH(port_count, struct port_key, u64, 10240);

int xdp_count(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    struct port_key key = {};
    key.protocol = ip->protocol;

    // Calculate IP header length
    int ip_hdr_len = ip->ihl * 4;
    void *transport = (void *)ip + ip_hdr_len;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = transport;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        key.port = ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = transport;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        key.port = ntohs(udp->dest);
    } else {
        return XDP_PASS;
    }

    u64 *count = port_count.lookup_or_try_init(&key, &(u64){0});
    if (count) (*count)++;

    return XDP_PASS;
}
"""

b = BPF(text=bpf_text)
fn = b.load_func("xdp_count", BPF.XDP)
b.attach_xdp(args.interface, fn, 0)

# Common port names
port_names = {
    22: "SSH", 80: "HTTP", 443: "HTTPS", 53: "DNS",
    3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-ALT", 25: "SMTP", 143: "IMAP", 993: "IMAPS"
}

try:
    while True:
        time.sleep(1)
        print("\033[2J\033[H")
        print(f"Top Destination Ports - {args.interface}")
        print(f"{'Protocol':<8} {'Port':>6} {'Service':<15} {'Packets':>15}")
        print("-" * 50)
        
        port_counts = []
        for k, v in b["port_count"].items():
            proto = "TCP" if k.protocol == 6 else "UDP"
            port = k.port
            service = port_names.get(port, "")
            port_counts.append((proto, port, service, v.value))
        
        sorted_ports = sorted(port_counts, key=lambda x: x[3], reverse=True)
        
        for proto, port, service, count in sorted_ports[:15]:
            print(f"{proto:<8} {port:>6} {service:<15} {count:>15,}")

except KeyboardInterrupt:
    pass
finally:
    b.remove_xdp(args.interface, 0)
```

## Step 5: Complete Solution with All Features

```python
#!/usr/bin/env python3
"""
Packet Counter - Complete Solution
XDP-based packet counter with protocol, IP, and port statistics.
"""
from bcc import BPF
import time
import argparse
import socket
import struct
import curses

parser = argparse.ArgumentParser(description="XDP Packet Counter")
parser.add_argument("interface", help="Network interface")
parser.add_argument("-i", "--interval", type=float, default=1.0, help="Update interval")
args = parser.parse_args()

bpf_text = r"""
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>

// Protocol counters
#define PROTO_TCP   0
#define PROTO_UDP   1
#define PROTO_ICMP  2
#define PROTO_OTHER 3

struct stats {
    u64 packets;
    u64 bytes;
};

struct ip_key {
    u32 addr;
};

struct port_key {
    u8 protocol;
    u16 port;
};

BPF_ARRAY(proto_stats, struct stats, 4);
BPF_HASH(src_ip_stats, struct ip_key, struct stats, 10240);
BPF_HASH(dst_port_stats, struct port_key, struct stats, 10240);
BPF_ARRAY(total_stats, struct stats, 1);

static __always_inline void update_stats(struct stats *s, u64 bytes) {
    if (s) {
        __sync_fetch_and_add(&s->packets, 1);
        __sync_fetch_and_add(&s->bytes, bytes);
    }
}

int xdp_counter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    u64 pkt_len = data_end - data;

    // Update total
    u32 zero = 0;
    struct stats *total = total_stats.lookup(&zero);
    update_stats(total, pkt_len);

    // Parse Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Update source IP stats
    struct ip_key ip_key = {.addr = ip->saddr};
    struct stats *ip_stats = src_ip_stats.lookup_or_try_init(&ip_key, 
                                                              &(struct stats){});
    update_stats(ip_stats, pkt_len);

    // Determine protocol and update stats
    u32 proto_idx;
    switch (ip->protocol) {
        case IPPROTO_TCP:  proto_idx = PROTO_TCP; break;
        case IPPROTO_UDP:  proto_idx = PROTO_UDP; break;
        case IPPROTO_ICMP: proto_idx = PROTO_ICMP; break;
        default: proto_idx = PROTO_OTHER;
    }

    struct stats *proto_stats_ptr = proto_stats.lookup(&proto_idx);
    update_stats(proto_stats_ptr, pkt_len);

    // Parse transport for port stats
    int ip_hdr_len = ip->ihl * 4;
    void *transport = (void *)ip + ip_hdr_len;

    struct port_key port_key = {.protocol = ip->protocol};

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = transport;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        port_key.port = ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = transport;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        port_key.port = ntohs(udp->dest);
    } else {
        return XDP_PASS;
    }

    struct stats *port_stats = dst_port_stats.lookup_or_try_init(&port_key, 
                                                                   &(struct stats){});
    update_stats(port_stats, pkt_len);

    return XDP_PASS;
}
"""

b = BPF(text=bpf_text)
fn = b.load_func("xdp_counter", BPF.XDP)
b.attach_xdp(args.interface, fn, 0)

def ip_to_str(ip_int):
    return socket.inet_ntoa(struct.pack("I", ip_int))

def format_bytes(b):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if b < 1024:
            return f"{b:7.1f}{unit}"
        b /= 1024
    return f"{b:7.1f}TB"

def format_rate(b):
    for unit in ['b/s', 'Kb/s', 'Mb/s', 'Gb/s']:
        if b < 1000:
            return f"{b:7.1f}{unit}"
        b /= 1000
    return f"{b:7.1f}Tb/s"

protocol_names = ["TCP", "UDP", "ICMP", "Other"]
port_names = {
    22: "SSH", 80: "HTTP", 443: "HTTPS", 53: "DNS",
    3306: "MySQL", 5432: "Postgres", 6379: "Redis",
    8080: "Alt-HTTP", 25: "SMTP", 8443: "HTTPS-Alt"
}

prev_total = (0, 0)
prev_proto = [(0, 0)] * 4

try:
    while True:
        time.sleep(args.interval)
        print("\033[2J\033[H")
        
        # Total stats
        total = b["total_stats"][0]
        pps = (total.packets - prev_total[0]) / args.interval
        bps = (total.bytes - prev_total[1]) * 8 / args.interval
        prev_total = (total.packets, total.bytes)
        
        print(f"╔══════════════════════════════════════════════════════════════════╗")
        print(f"║  Packet Counter - {args.interface:<15}                           ║")
        print(f"║  Total: {total.packets:>12,} pkts  {format_bytes(total.bytes):>10}  "
              f"│ {pps:>10,.0f} pps  {format_rate(bps):>12} ║")
        print(f"╠══════════════════════════════════════════════════════════════════╣")
        
        # Protocol breakdown
        print(f"║  {'Protocol':<10} {'Packets':>12} {'Bytes':>10} "
              f"│ {'pps':>10} {'Rate':>12} ║")
        print(f"║  {'─'*10} {'─'*12} {'─'*10} │ {'─'*10} {'─'*12} ║")
        
        for i, name in enumerate(protocol_names):
            stats = b["proto_stats"][i]
            pps = (stats.packets - prev_proto[i][0]) / args.interval
            bps = (stats.bytes - prev_proto[i][1]) * 8 / args.interval
            prev_proto[i] = (stats.packets, stats.bytes)
            
            print(f"║  {name:<10} {stats.packets:>12,} {format_bytes(stats.bytes):>10} "
                  f"│ {pps:>10,.0f} {format_rate(bps):>12} ║")
        
        print(f"╠══════════════════════════════════════════════════════════════════╣")
        
        # Top source IPs
        print(f"║  Top Source IPs                                                   ║")
        print(f"║  {'IP Address':<18} {'Packets':>12} {'Bytes':>12}               ║")
        
        ip_stats = []
        for k, v in b["src_ip_stats"].items():
            ip_stats.append((k.addr, v.packets, v.bytes))
        ip_stats.sort(key=lambda x: x[1], reverse=True)
        
        for addr, pkts, byts in ip_stats[:5]:
            print(f"║  {ip_to_str(addr):<18} {pkts:>12,} {format_bytes(byts):>12}               ║")
        
        print(f"╠══════════════════════════════════════════════════════════════════╣")
        
        # Top destination ports
        print(f"║  Top Destination Ports                                            ║")
        print(f"║  {'Proto':<6} {'Port':>6} {'Service':<10} {'Packets':>12} {'Bytes':>10}    ║")
        
        port_stats = []
        for k, v in b["dst_port_stats"].items():
            proto = "TCP" if k.protocol == 6 else "UDP"
            service = port_names.get(k.port, "")
            port_stats.append((proto, k.port, service, v.packets, v.bytes))
        port_stats.sort(key=lambda x: x[3], reverse=True)
        
        for proto, port, service, pkts, byts in port_stats[:5]:
            print(f"║  {proto:<6} {port:>6} {service:<10} {pkts:>12,} {format_bytes(byts):>10}    ║")
        
        print(f"╚══════════════════════════════════════════════════════════════════╝")
        print(f"\nPress Ctrl+C to exit")

except KeyboardInterrupt:
    pass
finally:
    b.remove_xdp(args.interface, 0)
    print("\nDetached XDP program")
```

## Testing

```bash
# Basic usage
sudo python3 packet_counter.py eth0

# Faster updates
sudo python3 packet_counter.py eth0 -i 0.5

# Generate traffic for testing
ping -c 100 8.8.8.8 &
curl -s https://example.com > /dev/null &
```

## Challenges

1. **IPv6 support**: Add parsing for IPv6 packets.

2. **Packet size histogram**: Track distribution of packet sizes.

3. **Flow tracking**: Count unique 5-tuples (src IP, dst IP, src port, dst port, proto).

4. **Drop statistics**: Track how many packets the kernel drops.

5. **Multi-interface**: Monitor multiple interfaces simultaneously.

## What's Next

In [Project 03: TCP Connect Logger](../project03-tcp-connect-logger/index.md), you'll trace TCP connection events with structured logging.
