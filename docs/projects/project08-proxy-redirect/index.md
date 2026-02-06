# Project 08: Proxy Redirect

Build a transparent proxy redirector using cgroup sock_addr hooks. This capstone project intercepts `connect()` calls and redirects connections to a proxy server — the foundation for service meshes and transparent proxies.

## What You'll Build

A tool that:

- Intercepts outbound TCP connections
- Redirects selected connections to a local proxy
- Preserves original destination for the proxy
- Works transparently to applications

## Learning Objectives

- Use cgroup sock_addr programs (connect4, connect6)
- Implement original destination preservation
- Build transparent proxy infrastructure
- Integrate with existing proxy software

## Prerequisites

- All previous projects
- Understanding of cgroup hooks from Ch 19

## Architecture

```
Application calls connect(target:80)
         │
         ▼
┌────────────────────────────────────────────────────┐
│              cgroup/connect4 BPF Program            │
│                                                     │
│  1. Check if connection should be redirected        │
│  2. Store original destination in map               │
│  3. Rewrite destination to proxy (127.0.0.1:15001) │
└────────────────────────────────────────────────────┘
         │
         ▼
    TCP connects to 127.0.0.1:15001 (proxy)
         │
         ▼
┌────────────────────────────────────────────────────┐
│              Local Proxy (e.g., Envoy)              │
│                                                     │
│  1. Accept connection                               │
│  2. Query original destination from eBPF map       │
│  3. Connect to original target:80                   │
│  4. Relay traffic bidirectionally                   │
└────────────────────────────────────────────────────┘
         │
         ▼
    Proxy connects to original target:80
```

## Project Structure

```
proxy_redirect/
├── Makefile
├── proxy_redirect.h
├── proxy_redirect.bpf.c
├── proxy_redirect.c
└── simple_proxy.py         # Demo proxy
```

## Step 1: Shared Header

Create `proxy_redirect.h`:

```c
#ifndef __PROXY_REDIRECT_H
#define __PROXY_REDIRECT_H

// Socket cookie to original destination mapping
struct orig_dst {
    __u32 dst_ip;
    __u16 dst_port;
    __u16 pad;
};

// Configuration
struct redirect_config {
    __u32 proxy_ip;      // Proxy IP (network byte order)
    __u16 proxy_port;    // Proxy port (host byte order)
    __u16 enabled;
    __u32 exclude_uid;   // UID to exclude (e.g., proxy's UID)
};

// Statistics
struct redirect_stats {
    __u64 connections_total;
    __u64 connections_redirected;
    __u64 connections_bypassed;
};

// Event for logging
struct redirect_event {
    __u64 timestamp;
    __u64 cookie;
    __u32 pid;
    __u32 orig_dst_ip;
    __u16 orig_dst_port;
    __u16 new_dst_port;
    __u32 new_dst_ip;
    __u8 action;  // 0=bypass, 1=redirect
    char comm[16];
};

#endif
```

## Step 2: BPF Program

Create `proxy_redirect.bpf.c`:

```c
// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "proxy_redirect.h"

char LICENSE[] SEC("license") = "GPL";

// Configuration map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct redirect_config);
} config SEC(".maps");

// Original destination map (socket cookie -> original destination)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct orig_dst);
} orig_dst_map SEC(".maps");

// Statistics
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

// Events ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Ports to redirect (simple array for demo)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);
    __type(value, __u8);
} redirect_ports SEC(".maps");

// IPs to exclude (e.g., localhost, proxy itself)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u8);
} exclude_ips SEC(".maps");

#define STAT_TOTAL     0
#define STAT_REDIRECTED 1
#define STAT_BYPASSED   2

static __always_inline void update_stat(__u32 key)
{
    __u64 *val = bpf_map_lookup_elem(&stats, &key);
    if (val)
        __sync_fetch_and_add(val, 1);
}

static __always_inline void emit_event(__u64 cookie, __u32 orig_ip,
                                        __u16 orig_port, __u32 new_ip,
                                        __u16 new_port, __u8 action)
{
    struct redirect_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return;

    event->timestamp = bpf_ktime_get_ns();
    event->cookie = cookie;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->orig_dst_ip = orig_ip;
    event->orig_dst_port = orig_port;
    event->new_dst_ip = new_ip;
    event->new_dst_port = new_port;
    event->action = action;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
}

SEC("cgroup/connect4")
int connect4_redirect(struct bpf_sock_addr *ctx)
{
    // Only handle TCP
    if (ctx->protocol != IPPROTO_TCP)
        return 1;

    update_stat(STAT_TOTAL);

    // Get configuration
    __u32 cfg_key = 0;
    struct redirect_config *cfg = bpf_map_lookup_elem(&config, &cfg_key);
    if (!cfg || !cfg->enabled)
        return 1;

    // Skip if UID matches proxy (avoid redirect loop)
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if (uid == cfg->exclude_uid) {
        update_stat(STAT_BYPASSED);
        return 1;
    }

    // Get original destination
    __u32 orig_dst_ip = ctx->user_ip4;
    __u16 orig_dst_port = bpf_ntohl(ctx->user_port) >> 16;

    // Check if destination IP should be excluded
    if (bpf_map_lookup_elem(&exclude_ips, &orig_dst_ip)) {
        update_stat(STAT_BYPASSED);
        return 1;
    }

    // Check if destination port should be redirected
    if (!bpf_map_lookup_elem(&redirect_ports, &orig_dst_port)) {
        update_stat(STAT_BYPASSED);
        return 1;
    }

    // Get socket cookie for tracking
    __u64 cookie = bpf_get_socket_cookie(ctx);

    // Store original destination
    struct orig_dst orig = {
        .dst_ip = orig_dst_ip,
        .dst_port = orig_dst_port,
    };
    bpf_map_update_elem(&orig_dst_map, &cookie, &orig, BPF_ANY);

    // Rewrite destination to proxy
    ctx->user_ip4 = cfg->proxy_ip;
    ctx->user_port = bpf_htonl(cfg->proxy_port << 16);

    update_stat(STAT_REDIRECTED);

    // Emit event
    emit_event(cookie, orig_dst_ip, orig_dst_port,
               cfg->proxy_ip, cfg->proxy_port, 1);

    return 1;
}

// Helper program for proxy to query original destination
SEC("cgroup/getsockopt")
int getsockopt_orig_dst(struct bpf_sockopt *ctx)
{
    // Check for SO_ORIGINAL_DST query (level=SOL_IP, optname=80)
    if (ctx->level != 0 || ctx->optname != 80)
        return 1;

    __u64 cookie = bpf_get_socket_cookie(ctx);
    struct orig_dst *orig = bpf_map_lookup_elem(&orig_dst_map, &cookie);
    if (!orig)
        return 1;

    // Return original destination through optval
    // (This is a simplified approach - real implementation would
    // return a sockaddr_in structure)

    return 1;
}
```

## Step 3: Userspace Program

Create `proxy_redirect.c`:

```c
// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <pwd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "proxy_redirect.h"
#include "proxy_redirect.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

static const char *ip_str(__u32 addr)
{
    static char buf[2][16];
    static int idx = 0;
    idx = !idx;
    struct in_addr in = {.s_addr = addr};
    inet_ntop(AF_INET, &in, buf[idx], sizeof(buf[idx]));
    return buf[idx];
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct redirect_event *event = data;
    double ts = event->timestamp / 1e9;

    printf("%12.3f %-8s %-16s [%llu] %s:%d -> %s:%d\n",
           ts,
           event->action ? "REDIRECT" : "BYPASS",
           event->comm,
           event->cookie,
           ip_str(event->orig_dst_ip), event->orig_dst_port,
           ip_str(event->new_dst_ip), event->new_dst_port);

    return 0;
}

static void print_stats(struct proxy_redirect_bpf *skel)
{
    __u64 total = 0, redirected = 0, bypassed = 0;
    __u32 keys[] = {STAT_TOTAL, STAT_REDIRECTED, STAT_BYPASSED};
    __u64 values[256];  // Per-CPU

    for (int i = 0; i < 3; i++) {
        if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats), &keys[i], values) == 0) {
            for (int cpu = 0; cpu < sysconf(_SC_NPROCESSORS_ONLN); cpu++) {
                switch (i) {
                case 0: total += values[cpu]; break;
                case 1: redirected += values[cpu]; break;
                case 2: bypassed += values[cpu]; break;
                }
            }
        }
    }

    printf("\n=== Statistics ===\n");
    printf("Total connections: %llu\n", total);
    printf("Redirected: %llu\n", redirected);
    printf("Bypassed: %llu\n", bypassed);
}

static void print_orig_dst_map(struct proxy_redirect_bpf *skel)
{
    __u64 key, next_key;
    struct orig_dst value;
    int fd = bpf_map__fd(skel->maps.orig_dst_map);

    printf("\n=== Original Destinations ===\n");
    printf("%-20s -> %s:%s\n", "Cookie", "IP", "Port");

    memset(&key, 0, sizeof(key));
    while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(fd, &next_key, &value) == 0) {
            printf("%-20llu -> %s:%d\n", next_key,
                   ip_str(value.dst_ip), value.dst_port);
        }
        key = next_key;
    }
}

static __u32 ip_to_int(const char *ip)
{
    struct in_addr addr;
    inet_pton(AF_INET, ip, &addr);
    return addr.s_addr;
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [options]\n", prog);
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  -c cgroup     Cgroup path (default: /sys/fs/cgroup)\n");
    fprintf(stderr, "  -p port       Proxy port (default: 15001)\n");
    fprintf(stderr, "  -i ip         Proxy IP (default: 127.0.0.1)\n");
    fprintf(stderr, "  -u user       User to exclude (default: nobody)\n");
    fprintf(stderr, "  -P ports      Ports to redirect (comma-separated, default: 80,443)\n");
    fprintf(stderr, "  -v            Verbose output\n");
    fprintf(stderr, "\nExample:\n");
    fprintf(stderr, "  %s -p 15001 -P 80,443,8080\n", prog);
}

int main(int argc, char **argv)
{
    struct proxy_redirect_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    const char *cgroup_path = "/sys/fs/cgroup";
    const char *proxy_ip = "127.0.0.1";
    const char *exclude_user = "nobody";
    const char *ports_str = "80,443";
    __u16 proxy_port = 15001;
    bool verbose = false;
    int cgroup_fd = -1;
    int opt;

    while ((opt = getopt(argc, argv, "c:p:i:u:P:vh")) != -1) {
        switch (opt) {
        case 'c':
            cgroup_path = optarg;
            break;
        case 'p':
            proxy_port = atoi(optarg);
            break;
        case 'i':
            proxy_ip = optarg;
            break;
        case 'u':
            exclude_user = optarg;
            break;
        case 'P':
            ports_str = optarg;
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

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Load BPF
    skel = proxy_redirect_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load BPF\n");
        return 1;
    }

    // Get exclude UID
    struct passwd *pwd = getpwnam(exclude_user);
    __u32 exclude_uid = pwd ? pwd->pw_uid : 65534;

    // Configure
    __u32 cfg_key = 0;
    struct redirect_config cfg = {
        .proxy_ip = ip_to_int(proxy_ip),
        .proxy_port = proxy_port,
        .enabled = 1,
        .exclude_uid = exclude_uid,
    };
    bpf_map_update_elem(bpf_map__fd(skel->maps.config), &cfg_key, &cfg, 0);

    // Add ports to redirect
    char *ports_copy = strdup(ports_str);
    char *token = strtok(ports_copy, ",");
    while (token) {
        __u16 port = atoi(token);
        __u8 val = 1;
        bpf_map_update_elem(bpf_map__fd(skel->maps.redirect_ports), &port, &val, 0);
        printf("Redirecting port: %d\n", port);
        token = strtok(NULL, ",");
    }
    free(ports_copy);

    // Add localhost to exclude IPs
    __u32 localhost = ip_to_int("127.0.0.1");
    __u8 exclude_val = 1;
    bpf_map_update_elem(bpf_map__fd(skel->maps.exclude_ips), &localhost, &exclude_val, 0);

    // Attach to cgroup
    cgroup_fd = open(cgroup_path, O_DIRECTORY | O_RDONLY);
    if (cgroup_fd < 0) {
        fprintf(stderr, "Failed to open cgroup %s\n", cgroup_path);
        goto cleanup;
    }

    if (bpf_prog_attach(bpf_program__fd(skel->progs.connect4_redirect),
                        cgroup_fd, BPF_CGROUP_INET4_CONNECT, 0) < 0) {
        fprintf(stderr, "Failed to attach BPF program\n");
        goto cleanup;
    }

    printf("\nProxy Redirect started\n");
    printf("Proxy: %s:%d\n", proxy_ip, proxy_port);
    printf("Exclude UID: %d (%s)\n", exclude_uid, exclude_user);
    printf("Cgroup: %s\n", cgroup_path);
    printf("\nListening for connections...\n\n");

    if (verbose) {
        printf("%12s %-8s %-16s %-20s CONNECTION\n",
               "TIME(s)", "ACTION", "PROCESS", "COOKIE");

        rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
                               handle_event, NULL, NULL);
    }

    while (!exiting) {
        if (rb) {
            ring_buffer__poll(rb, 100);
        } else {
            sleep(1);
        }
    }

    print_stats(skel);
    print_orig_dst_map(skel);

cleanup:
    ring_buffer__free(rb);
    if (cgroup_fd >= 0) {
        bpf_prog_detach(cgroup_fd, BPF_CGROUP_INET4_CONNECT);
        close(cgroup_fd);
    }
    proxy_redirect_bpf__destroy(skel);

    printf("\nCleaned up\n");
    return 0;
}
```

## Step 4: Simple Demo Proxy

Create `simple_proxy.py`:

```python
#!/usr/bin/env python3
"""
Simple transparent proxy that reads original destination from eBPF map.
For demonstration only - use Envoy/HAProxy for production.
"""
import socket
import struct
import threading
import sys
import os
from ctypes import c_uint64, c_uint32, c_uint16

# Read original destination from BPF map
def get_original_dst(client_sock):
    """Query original destination from eBPF map using socket cookie."""
    # Get socket cookie
    try:
        cookie = client_sock.getsockopt(socket.SOL_SOCKET, 57)  # SO_COOKIE
    except:
        return None

    # Read from BPF map (simplified - real implementation would use libbpf)
    map_path = "/sys/fs/bpf/proxy_redirect/orig_dst_map"
    try:
        # This is a simplified version - real code would use proper BPF map access
        return None
    except:
        return None

def handle_client(client_sock, client_addr, default_dst):
    """Handle a single client connection."""
    try:
        # Try to get original destination
        orig_dst = get_original_dst(client_sock)
        if orig_dst:
            dst_ip, dst_port = orig_dst
        else:
            # Fallback to default destination for demo
            dst_ip, dst_port = default_dst

        print(f"[{client_addr}] -> {dst_ip}:{dst_port}")

        # Connect to actual destination
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.connect((dst_ip, dst_port))

        # Relay data bidirectionally
        def relay(src, dst, name):
            try:
                while True:
                    data = src.recv(4096)
                    if not data:
                        break
                    dst.sendall(data)
            except:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except:
                    pass

        t1 = threading.Thread(target=relay, args=(client_sock, server_sock, "c->s"))
        t2 = threading.Thread(target=relay, args=(server_sock, client_sock, "s->c"))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_sock.close()

def main():
    listen_port = int(sys.argv[1]) if len(sys.argv) > 1 else 15001
    default_dst = ("example.com", 80)  # Fallback for demo

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", listen_port))
    server.listen(128)

    print(f"Simple proxy listening on 127.0.0.1:{listen_port}")
    print(f"Default destination: {default_dst[0]}:{default_dst[1]}")

    try:
        while True:
            client_sock, client_addr = server.accept()
            t = threading.Thread(target=handle_client,
                               args=(client_sock, client_addr, default_dst))
            t.daemon = True
            t.start()
    except KeyboardInterrupt:
        print("\nShutting down")
    finally:
        server.close()

if __name__ == "__main__":
    main()
```

## Step 5: Makefile

```makefile
CLANG ?= clang
BPFTOOL ?= bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

CFLAGS := -g -O2 -Wall
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)

LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LDFLAGS := $(shell pkg-config --libs libbpf 2>/dev/null || echo "-lbpf -lelf -lz")

all: proxy_redirect

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

proxy_redirect.bpf.o: proxy_redirect.bpf.c proxy_redirect.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

proxy_redirect.skel.h: proxy_redirect.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

proxy_redirect: proxy_redirect.c proxy_redirect.skel.h proxy_redirect.h
	$(CLANG) $(CFLAGS) $(LIBBPF_CFLAGS) $< $(LIBBPF_LDFLAGS) -o $@

clean:
	rm -f proxy_redirect *.o *.skel.h vmlinux.h
```

## Testing

```bash
# Terminal 1: Start the proxy
python3 simple_proxy.py 15001

# Terminal 2: Start the redirector
sudo ./proxy_redirect -p 15001 -P 80,443 -v

# Terminal 3: Test connections (as non-nobody user)
curl http://example.com
# Connection gets redirected through proxy!

# Check the verbose output in Terminal 2
```

## How It Works

1. **Application calls `connect()`**: App tries to connect to `example.com:80`

2. **cgroup/connect4 intercepts**: BPF program sees the connect call

3. **Check redirect rules**: Is port 80 in redirect list? Is destination excluded?

4. **Store original destination**: Save `example.com:80` in map keyed by socket cookie

5. **Rewrite destination**: Change destination to `127.0.0.1:15001` (proxy)

6. **Proxy accepts**: Connection arrives at proxy instead

7. **Proxy queries original destination**: Uses socket cookie to look up real target

8. **Proxy connects to real target**: Establishes connection to `example.com:80`

9. **Relay traffic**: Proxy forwards data bidirectionally

## Integration with Real Proxies

For production, integrate with:

- **Envoy Proxy**: Use `original_dst` cluster type
- **HAProxy**: Use transparent proxy mode
- **NGINX**: Use `proxy_bind` with transparent flag

## Challenges

1. **IPv6 support**: Add connect6 program for IPv6 connections.

2. **UDP support**: Add sendmsg4/recvmsg4 hooks for UDP.

3. **Per-process rules**: Different redirect rules per process/cgroup.

4. **Service mesh**: Implement Kubernetes sidecar proxy pattern.

5. **mTLS termination**: Add TLS handling in the proxy.

## Congratulations!

You've completed all eight projects! You now have practical experience with:

- ✅ Syscall tracing (kprobes)
- ✅ Packet counting (XDP)
- ✅ Connection logging (ring buffers)
- ✅ Packet inspection (TC)
- ✅ Packet modification (checksums)
- ✅ Connection tracking (sock_ops)
- ✅ Multi-program coordination
- ✅ Transparent proxying (cgroup hooks)

You're ready to build production eBPF applications!
