# Chapter 25: Socket Filtering

Socket filters let you attach eBPF programs directly to sockets, filtering which packets an application receives. This is the classic BPF use case — `tcpdump` has used socket filters for decades.

## Socket Filter Basics

A socket filter attaches to a socket and decides which packets pass to the application:

```
┌─────────────────────────────────────┐
│           Application               │
│         (recv(), read())            │
└───────────────┬─────────────────────┘
                │
                │ Only allowed packets
                │
┌───────────────┴─────────────────────┐
│      Socket Filter (eBPF)           │
│   return 0 = drop, >0 = pass        │
└───────────────┬─────────────────────┘
                │
                │ All packets
                │
┌───────────────┴─────────────────────┐
│         Network Stack               │
└─────────────────────────────────────┘
```

## Return Values

For socket filters:

| Return | Meaning |
|--------|---------|
| 0 | Drop packet (application won't see it) |
| length | Pass packet (truncate to this length) |
| `skb->len` | Pass full packet |

## Classic BPF Example

For comparison, here's classic BPF (tcpdump uses this):

```python
# Python with socket and SO_ATTACH_FILTER
import socket
import struct

# Classic BPF filter for ICMP
BPF_FILTER = [
    # Load EtherType
    (0x28, 0, 0, 12),      # ldh [12]
    # Skip if not IP
    (0x15, 0, 3, 0x0800),  # jeq #0x800, L1, L4
    # Load IP protocol
    (0x30, 0, 0, 23),      # ldb [23]
    # Keep if ICMP
    (0x15, 0, 1, 1),       # jeq #1, L3, L4
    # Accept
    (0x06, 0, 0, 65535),   # ret #65535
    # Reject
    (0x06, 0, 0, 0),       # ret #0
]

def attach_filter(sock, bpf_filter):
    # Encode BPF program
    filters = b''.join(struct.pack('HBBI', *f) for f in bpf_filter)
    fprog = struct.pack('HL', len(bpf_filter), 0) + filters
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_ATTACH_FILTER, fprog)
```

## eBPF Socket Filter

Modern eBPF approach:

=== "BCC"

    ```python
    #!/usr/bin/env python3
    from bcc import BPF
    import socket
    import os

    program = r"""
    #include <linux/bpf.h>
    #include <linux/if_ether.h>
    #include <linux/ip.h>

    int filter_icmp(struct __sk_buff *skb) {
        void *data = (void *)(long)skb->data;
        void *data_end = (void *)(long)skb->data_end;

        struct ethhdr *eth = data;
        if ((void *)(eth + 1) > data_end)
            return 0;

        if (eth->h_proto != htons(ETH_P_IP))
            return 0;

        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return 0;

        // Only pass ICMP packets
        if (ip->protocol == IPPROTO_ICMP)
            return skb->len;

        return 0;  // Drop non-ICMP
    }
    """

    b = BPF(text=program)
    func = b.load_func("filter_icmp", BPF.SOCKET_FILTER)

    # Create raw socket
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    sock.bind(("eth0", 0))

    # Attach filter
    sock.setsockopt(socket.SOL_SOCKET, 50, func.fd)  # SO_ATTACH_BPF = 50

    print("Filtering for ICMP packets...")
    while True:
        packet = sock.recv(65535)
        print(f"Received {len(packet)} bytes")
    ```

=== "libbpf"

    ```c
    // socket_filter.bpf.c
    #include "vmlinux.h"
    #include <bpf/bpf_helpers.h>
    #include <bpf/bpf_endian.h>

    SEC("socket")
    int filter_icmp(struct __sk_buff *skb) {
        // For socket filters, data access is different
        __u8 ip_proto;

        // Load IP protocol byte
        if (bpf_skb_load_bytes(skb, ETH_HLEN + 9, &ip_proto, 1) < 0)
            return 0;

        if (ip_proto == IPPROTO_ICMP)
            return skb->len;

        return 0;
    }

    char LICENSE[] SEC("license") = "GPL";
    ```

## Attaching to Sockets

### Using BCC

```python
from bcc import BPF
import socket

b = BPF(text=program)
func = b.load_func("my_filter", BPF.SOCKET_FILTER)

# Raw socket
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
sock.setsockopt(socket.SOL_SOCKET, 50, func.fd)  # SO_ATTACH_BPF

# Regular socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, 50, func.fd)
```

### Using libbpf

```c
#include <sys/socket.h>
#include <linux/bpf.h>

int prog_fd = bpf_program__fd(skel->progs.filter_icmp);

// Attach to socket
int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd));
```

## Filter by Port

```c
SEC("socket")
int filter_http(struct __sk_buff *skb) {
    __u8 ip_proto;
    __be16 dport;

    // Skip non-IP
    __be16 eth_proto;
    bpf_skb_load_bytes(skb, 12, &eth_proto, 2);
    if (eth_proto != bpf_htons(ETH_P_IP))
        return 0;

    // Get IP protocol
    bpf_skb_load_bytes(skb, ETH_HLEN + 9, &ip_proto, 1);
    if (ip_proto != IPPROTO_TCP)
        return 0;

    // Get IP header length
    __u8 ihl;
    bpf_skb_load_bytes(skb, ETH_HLEN, &ihl, 1);
    ihl = (ihl & 0x0F) * 4;

    // Get destination port
    bpf_skb_load_bytes(skb, ETH_HLEN + ihl + 2, &dport, 2);

    // Pass only HTTP (port 80)
    if (dport == bpf_htons(80))
        return skb->len;

    return 0;
}
```

## Filter by IP Address

```c
SEC("socket")
int filter_by_ip(struct __sk_buff *skb) {
    __be32 src_ip;

    // Load source IP
    bpf_skb_load_bytes(skb, ETH_HLEN + 12, &src_ip, 4);

    // Only pass packets from 192.168.1.0/24
    if ((src_ip & bpf_htonl(0xFFFFFF00)) == bpf_htonl(0xC0A80100))
        return skb->len;

    return 0;
}
```

## Using Maps for Dynamic Filtering

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __be32);     // IP address
    __type(value, __u8);     // 1 = allow
} allowed_ips SEC(".maps");

SEC("socket")
int filter_allowed(struct __sk_buff *skb) {
    __be32 src_ip;

    bpf_skb_load_bytes(skb, ETH_HLEN + 12, &src_ip, 4);

    __u8 *allowed = bpf_map_lookup_elem(&allowed_ips, &src_ip);
    if (allowed)
        return skb->len;

    return 0;
}
```

Update allowed IPs from userspace:

```python
# Add allowed IP
allowed_ips = b["allowed_ips"]
ip_int = struct.unpack("<I", socket.inet_aton("192.168.1.100"))[0]
allowed_ips[ctypes.c_uint32(ip_int)] = ctypes.c_uint8(1)

# Remove
del allowed_ips[ctypes.c_uint32(ip_int)]
```

## Packet Sampling

Accept every Nth packet:

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} counter SEC(".maps");

#define SAMPLE_RATE 100  // Keep 1 in 100 packets

SEC("socket")
int sample_packets(struct __sk_buff *skb) {
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&counter, &key);
    if (!count)
        return 0;

    (*count)++;

    // Keep every 100th packet
    if (*count % SAMPLE_RATE == 0)
        return skb->len;

    return 0;
}
```

## Truncating Packets

Return less than `skb->len` to truncate:

```c
SEC("socket")
int capture_headers(struct __sk_buff *skb) {
    // Only capture first 64 bytes (headers)
    if (skb->len > 64)
        return 64;

    return skb->len;
}
```

## BPF_PROG_TYPE_SOCKET_FILTER vs Others

| Type | Attach Point | Can Modify |
|------|--------------|------------|
| SOCKET_FILTER | Individual socket | No (read-only) |
| CGROUP_SKB | Cgroup | No |
| SCHED_CLS (TC) | Interface | Yes |
| XDP | Interface | Yes |

Socket filters are **read-only** — they can't modify packets, only filter them.

## Efficient Pattern Matching

Match specific payload patterns (e.g., HTTP GET):

```c
SEC("socket")
int filter_http_get(struct __sk_buff *skb) {
    __u8 ip_proto;
    bpf_skb_load_bytes(skb, ETH_HLEN + 9, &ip_proto, 1);
    if (ip_proto != IPPROTO_TCP)
        return 0;

    // Get IP header length
    __u8 ihl;
    bpf_skb_load_bytes(skb, ETH_HLEN, &ihl, 1);
    ihl = (ihl & 0x0F) * 4;

    // Get TCP header length
    __u8 doff;
    bpf_skb_load_bytes(skb, ETH_HLEN + ihl + 12, &doff, 1);
    __u32 tcp_hlen = (doff >> 4) * 4;

    // Calculate payload offset
    __u32 payload_off = ETH_HLEN + ihl + tcp_hlen;

    // Check for "GET " at start of payload
    __u32 magic;
    if (bpf_skb_load_bytes(skb, payload_off, &magic, 4) < 0)
        return 0;

    // "GET " in little-endian
    if (magic == 0x20544547)  // " TEG" backwards
        return skb->len;

    return 0;
}
```

## Complete Example: Custom Packet Capture

```python
#!/usr/bin/env python3
"""
Custom packet capture with eBPF filtering.
Only captures TCP SYN packets.
"""
from bcc import BPF
import socket
import struct

program = r"""
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

BPF_PERCPU_ARRAY(stats, u64, 3);  // [total, filtered, passed]

int filter_syn(struct __sk_buff *skb) {
    u32 idx = 0;
    u64 *total = stats.lookup(&idx);
    if (total) (*total)++;

    // Check EtherType
    u16 eth_proto;
    bpf_skb_load_bytes(skb, 12, &eth_proto, 2);
    if (eth_proto != htons(ETH_P_IP)) {
        idx = 1;
        u64 *filtered = stats.lookup(&idx);
        if (filtered) (*filtered)++;
        return 0;
    }

    // Check IP protocol
    u8 ip_proto;
    bpf_skb_load_bytes(skb, ETH_HLEN + 9, &ip_proto, 1);
    if (ip_proto != IPPROTO_TCP) {
        idx = 1;
        u64 *filtered = stats.lookup(&idx);
        if (filtered) (*filtered)++;
        return 0;
    }

    // Get IP header length
    u8 ihl;
    bpf_skb_load_bytes(skb, ETH_HLEN, &ihl, 1);
    ihl = (ihl & 0x0F) * 4;

    // Check TCP flags (SYN bit)
    u8 flags;
    bpf_skb_load_bytes(skb, ETH_HLEN + ihl + 13, &flags, 1);

    // SYN flag is bit 1, but not ACK (bit 4)
    if ((flags & 0x02) && !(flags & 0x10)) {
        idx = 2;
        u64 *passed = stats.lookup(&idx);
        if (passed) (*passed)++;
        return skb->len;  // Pass SYN packet
    }

    idx = 1;
    u64 *filtered = stats.lookup(&idx);
    if (filtered) (*filtered)++;
    return 0;
}
"""

b = BPF(text=program)
func = b.load_func("filter_syn", BPF.SOCKET_FILTER)

# Create raw socket
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
sock.setsockopt(socket.SOL_SOCKET, 50, func.fd)

print("Capturing TCP SYN packets... Ctrl+C to stop")

try:
    while True:
        packet, addr = sock.recvfrom(65535)

        # Parse minimally to show info
        eth_proto = struct.unpack("!H", packet[12:14])[0]
        if eth_proto == 0x0800:  # IP
            src_ip = socket.inet_ntoa(packet[26:30])
            dst_ip = socket.inet_ntoa(packet[30:34])
            src_port = struct.unpack("!H", packet[34:36])[0]
            dst_port = struct.unpack("!H", packet[36:38])[0]
            print(f"SYN: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

except KeyboardInterrupt:
    pass

# Print stats
print("\nStatistics:")
stats = b["stats"]
print(f"  Total packets:    {sum(stats[0])}")
print(f"  Filtered out:     {sum(stats[1])}")
print(f"  Passed (SYNs):    {sum(stats[2])}")
```

## SO_REUSEPORT with eBPF

Distribute incoming connections across multiple processes:

```c
struct {
    __uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u64);
} reuseport_array SEC(".maps");

SEC("sk_reuseport")
int select_socket(struct sk_reuseport_md *ctx) {
    // Simple: select based on CPU
    __u32 cpu = bpf_get_smp_processor_id();
    return bpf_sk_select_reuseport(ctx, &reuseport_array, &cpu, 0);
}
```

## Exercises

1. **DNS filter**: Only pass DNS packets (UDP port 53).

2. **Size filter**: Only pass packets larger than 1000 bytes.

3. **Sampling**: Implement random sampling (1% of packets).

4. **Pattern match**: Filter for HTTP responses (look for "HTTP/1.1").

5. **Time-based**: Only pass packets during certain hours (use `bpf_ktime_get_ns()`).

6. **Flow filter**: Pass only the first 10 packets of each new TCP connection.
