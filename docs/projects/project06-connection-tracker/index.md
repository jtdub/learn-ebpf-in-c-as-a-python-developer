# Project 06: Connection Tracker

Build a connection tracker using sock_ops programs that monitors TCP connection lifecycle events. This provides deeper visibility than packet-level inspection by hooking directly into socket operations.

## What You'll Build

A tool that:

- Tracks TCP connection establishment and teardown
- Monitors connection state transitions
- Calculates RTT and throughput metrics
- Provides per-connection statistics

## Learning Objectives

- Write sock_ops BPF programs
- Handle socket callback events
- Track connection state with BPF maps
- Calculate network metrics in kernel

## Prerequisites

- Projects 1-5
- Ch 18: Socket Syscalls
- Ch 19: Cgroup Hooks

## Architecture

```
┌─────────────────────────────────────────────────┐
│                Application                       │
│     connect()     send()     recv()    close()  │
└────────┬───────────┬──────────┬──────────┬──────┘
         │           │          │          │
         ▼           ▼          ▼          ▼
┌─────────────────────────────────────────────────┐
│               sock_ops BPF Program               │
│                                                  │
│  BPF_SOCK_OPS_TCP_CONNECT_CB                    │
│  BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB             │
│  BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB            │
│  BPF_SOCK_OPS_STATE_CB                          │
│  BPF_SOCK_OPS_RTT_CB                            │
└─────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────┐
│              Connection Map                      │
│  5-tuple → {state, rtt, bytes, timestamps...}   │
└─────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────┐
│            Userspace Monitor                     │
│  - Display active connections                    │
│  - Show metrics                                  │
│  - Export to JSON                               │
└─────────────────────────────────────────────────┘
```

## Project Structure

```
connection_tracker/
├── Makefile
├── connection_tracker.bpf.c
├── connection_tracker.h
└── connection_tracker.c
```

## Step 1: Shared Header

Create `connection_tracker.h`:

```c
#ifndef __CONNECTION_TRACKER_H
#define __CONNECTION_TRACKER_H

// Connection key (5-tuple)
struct conn_id {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

// Connection state
enum conn_state {
    CONN_NEW = 0,
    CONN_CONNECTING,
    CONN_ESTABLISHED,
    CONN_CLOSING,
    CONN_CLOSED,
};

// Connection info
struct conn_info {
    __u64 start_ts;         // Connection start timestamp
    __u64 established_ts;   // When connection was established
    __u64 close_ts;         // When connection closed
    __u64 bytes_sent;       // Total bytes sent
    __u64 bytes_recv;       // Total bytes received
    __u64 packets_sent;     // Packets sent
    __u64 packets_recv;     // Packets received
    __u32 last_rtt;         // Last measured RTT (us)
    __u32 min_rtt;          // Minimum RTT (us)
    __u32 max_rtt;          // Maximum RTT (us)
    __u32 sum_rtt;          // Sum of RTT (for average)
    __u32 rtt_count;        // Number of RTT samples
    __u32 pid;              // Process ID
    __u8 state;             // Current state
    __u8 is_server;         // 1 if passive (server side)
    char comm[16];          // Process name
};

// Event types
enum event_type {
    EVENT_CONNECT = 1,
    EVENT_ACCEPT,
    EVENT_ESTABLISHED,
    EVENT_CLOSE,
    EVENT_RTT,
};

// Event structure
struct conn_event {
    __u64 timestamp;
    struct conn_id id;
    __u32 pid;
    __u32 rtt;
    __u8 event_type;
    __u8 state;
    char comm[16];
};

#endif
```

## Step 2: BPF Program

Create `connection_tracker.bpf.c`:

```c
// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include "connection_tracker.h"

char LICENSE[] SEC("license") = "GPL";

// Connection tracking map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct conn_id);
    __type(value, struct conn_info);
} connections SEC(".maps");

// Events ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Statistics
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

#define STAT_CONNECTS      0
#define STAT_ACCEPTS       1
#define STAT_ESTABLISHED   2
#define STAT_CLOSED        3
#define STAT_ACTIVE        4

static __always_inline void update_stat(__u32 key, __s64 delta)
{
    __u64 *val = bpf_map_lookup_elem(&stats, &key);
    if (val)
        __sync_fetch_and_add(val, delta);
}

static __always_inline void emit_event(struct conn_id *id, __u8 event_type,
                                        __u32 pid, __u32 rtt, __u8 state)
{
    struct conn_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return;

    event->timestamp = bpf_ktime_get_ns();
    event->id = *id;
    event->event_type = event_type;
    event->pid = pid;
    event->rtt = rtt;
    event->state = state;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
}

static __always_inline void extract_conn_id(struct bpf_sock_ops *skops,
                                             struct conn_id *id)
{
    id->src_ip = skops->local_ip4;
    id->dst_ip = skops->remote_ip4;
    id->src_port = skops->local_port;
    id->dst_port = bpf_ntohl(skops->remote_port) >> 16;
}

SEC("sockops")
int connection_tracker(struct bpf_sock_ops *skops)
{
    // Only handle IPv4 TCP
    if (skops->family != AF_INET)
        return 0;

    struct conn_id id;
    extract_conn_id(skops, &id);

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 now = bpf_ktime_get_ns();

    switch (skops->op) {
    case BPF_SOCK_OPS_TCP_CONNECT_CB: {
        // Active connection attempt (client)
        struct conn_info info = {
            .start_ts = now,
            .state = CONN_CONNECTING,
            .pid = pid,
            .min_rtt = ~0U,  // Initialize to max
        };
        bpf_get_current_comm(&info.comm, sizeof(info.comm));

        bpf_map_update_elem(&connections, &id, &info, BPF_ANY);
        emit_event(&id, EVENT_CONNECT, pid, 0, CONN_CONNECTING);
        update_stat(STAT_CONNECTS, 1);
        break;
    }

    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: {
        // Client-side connection established
        struct conn_info *info = bpf_map_lookup_elem(&connections, &id);
        if (info) {
            info->established_ts = now;
            info->state = CONN_ESTABLISHED;
        } else {
            // Connection not tracked, create entry
            struct conn_info new_info = {
                .start_ts = now,
                .established_ts = now,
                .state = CONN_ESTABLISHED,
                .pid = pid,
                .min_rtt = ~0U,
            };
            bpf_get_current_comm(&new_info.comm, sizeof(new_info.comm));
            bpf_map_update_elem(&connections, &id, &new_info, BPF_ANY);
        }

        // Enable RTT notifications
        bpf_sock_ops_cb_flags_set(skops,
            skops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_RTT_CB_FLAG);

        emit_event(&id, EVENT_ESTABLISHED, pid, 0, CONN_ESTABLISHED);
        update_stat(STAT_ESTABLISHED, 1);
        update_stat(STAT_ACTIVE, 1);
        break;
    }

    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: {
        // Server-side connection established
        struct conn_info info = {
            .start_ts = now,
            .established_ts = now,
            .state = CONN_ESTABLISHED,
            .pid = pid,
            .is_server = 1,
            .min_rtt = ~0U,
        };
        bpf_get_current_comm(&info.comm, sizeof(info.comm));

        bpf_map_update_elem(&connections, &id, &info, BPF_ANY);

        // Enable RTT notifications
        bpf_sock_ops_cb_flags_set(skops,
            skops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_RTT_CB_FLAG);

        emit_event(&id, EVENT_ACCEPT, pid, 0, CONN_ESTABLISHED);
        update_stat(STAT_ACCEPTS, 1);
        update_stat(STAT_ESTABLISHED, 1);
        update_stat(STAT_ACTIVE, 1);
        break;
    }

    case BPF_SOCK_OPS_STATE_CB: {
        // State change notification
        int old_state = skops->args[0];
        int new_state = skops->args[1];

        // Check for connection close (TCP_CLOSE)
        if (new_state == 7) {  // TCP_CLOSE
            struct conn_info *info = bpf_map_lookup_elem(&connections, &id);
            if (info) {
                info->close_ts = now;
                info->state = CONN_CLOSED;

                emit_event(&id, EVENT_CLOSE, info->pid,
                          info->rtt_count ? info->sum_rtt / info->rtt_count : 0,
                          CONN_CLOSED);
            }

            update_stat(STAT_CLOSED, 1);
            update_stat(STAT_ACTIVE, -1);

            // Remove from map after short delay
            bpf_map_delete_elem(&connections, &id);
        }
        break;
    }

    case BPF_SOCK_OPS_RTT_CB: {
        // RTT measurement callback
        __u32 rtt = skops->srtt_us >> 3;  // srtt is scaled by 8

        struct conn_info *info = bpf_map_lookup_elem(&connections, &id);
        if (info) {
            info->last_rtt = rtt;
            info->sum_rtt += rtt;
            info->rtt_count++;

            if (rtt < info->min_rtt)
                info->min_rtt = rtt;
            if (rtt > info->max_rtt)
                info->max_rtt = rtt;

            emit_event(&id, EVENT_RTT, info->pid, rtt, info->state);
        }
        break;
    }
    }

    return 0;
}
```

## Step 3: Userspace Program

Create `connection_tracker.c`:

```c
// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>

#include "connection_tracker.h"
#include "connection_tracker.skel.h"

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

static const char *state_str(__u8 state)
{
    switch (state) {
    case CONN_NEW:        return "NEW";
    case CONN_CONNECTING: return "CONNECTING";
    case CONN_ESTABLISHED: return "ESTABLISHED";
    case CONN_CLOSING:    return "CLOSING";
    case CONN_CLOSED:     return "CLOSED";
    default:              return "UNKNOWN";
    }
}

static const char *event_str(__u8 event)
{
    switch (event) {
    case EVENT_CONNECT:     return "CONNECT";
    case EVENT_ACCEPT:      return "ACCEPT";
    case EVENT_ESTABLISHED: return "ESTABLISHED";
    case EVENT_CLOSE:       return "CLOSE";
    case EVENT_RTT:         return "RTT";
    default:                return "UNKNOWN";
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct conn_event *event = data;
    double ts = event->timestamp / 1e9;

    // Skip RTT events unless verbose
    bool *verbose = ctx;
    if (event->event_type == EVENT_RTT && !*verbose)
        return 0;

    printf("%12.3f %-11s %-16s %s:%d -> %s:%d",
           ts, event_str(event->event_type), event->comm,
           ip_str(event->id.src_ip), event->id.src_port,
           ip_str(event->id.dst_ip), event->id.dst_port);

    if (event->event_type == EVENT_RTT) {
        printf(" RTT=%uus", event->rtt);
    }

    printf("\n");
    return 0;
}

static void print_connections(struct connection_tracker_bpf *skel)
{
    struct conn_id key, next_key;
    struct conn_info info;
    int fd = bpf_map__fd(skel->maps.connections);

    printf("\n╔════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                           Active Connections                                ║\n");
    printf("╠════════════════════════════════════════════════════════════════════════════╣\n");
    printf("║ %-16s %-21s %-21s %8s ║\n",
           "Process", "Local", "Remote", "RTT(us)");
    printf("╠════════════════════════════════════════════════════════════════════════════╣\n");

    memset(&key, 0, sizeof(key));
    int count = 0;

    while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(fd, &next_key, &info) == 0) {
            if (info.state == CONN_ESTABLISHED) {
                char local[32], remote[32];
                snprintf(local, sizeof(local), "%s:%d",
                         ip_str(next_key.src_ip), next_key.src_port);
                snprintf(remote, sizeof(remote), "%s:%d",
                         ip_str(next_key.dst_ip), next_key.dst_port);

                __u32 avg_rtt = info.rtt_count ? info.sum_rtt / info.rtt_count : 0;

                printf("║ %-16s %-21s %-21s %8u ║\n",
                       info.comm, local, remote, avg_rtt);
                count++;
            }
        }
        key = next_key;
    }

    if (count == 0) {
        printf("║                        No active connections                               ║\n");
    }
    printf("╚════════════════════════════════════════════════════════════════════════════╝\n");
}

static void print_stats(struct connection_tracker_bpf *skel)
{
    __u64 values[8];
    __u32 keys[] = {STAT_CONNECTS, STAT_ACCEPTS, STAT_ESTABLISHED, STAT_CLOSED, STAT_ACTIVE};

    printf("\n=== Statistics ===\n");

    for (int i = 0; i < 5; i++) {
        bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats), &keys[i], &values[i]);
    }

    printf("Connect attempts: %llu\n", values[0]);
    printf("Connections accepted: %llu\n", values[1]);
    printf("Total established: %llu\n", values[2]);
    printf("Total closed: %llu\n", values[3]);
    printf("Currently active: %lld\n", (long long)values[4]);
}

static int attach_cgroup(int prog_fd, const char *cgroup_path)
{
    int cgroup_fd = open(cgroup_path, O_DIRECTORY | O_RDONLY);
    if (cgroup_fd < 0) {
        fprintf(stderr, "Failed to open cgroup %s\n", cgroup_path);
        return -1;
    }

    if (bpf_prog_attach(prog_fd, cgroup_fd, BPF_CGROUP_SOCK_OPS, 0) < 0) {
        fprintf(stderr, "Failed to attach to cgroup\n");
        close(cgroup_fd);
        return -1;
    }

    return cgroup_fd;
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [-c cgroup] [-l] [-v]\n", prog);
    fprintf(stderr, "  -c cgroup   Cgroup path (default: /sys/fs/cgroup)\n");
    fprintf(stderr, "  -l          List active connections periodically\n");
    fprintf(stderr, "  -v          Verbose (show RTT events)\n");
}

int main(int argc, char **argv)
{
    struct connection_tracker_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    const char *cgroup_path = "/sys/fs/cgroup";
    bool list_mode = false;
    bool verbose = false;
    int cgroup_fd = -1;
    int opt;

    while ((opt = getopt(argc, argv, "c:lvh")) != -1) {
        switch (opt) {
        case 'c':
            cgroup_path = optarg;
            break;
        case 'l':
            list_mode = true;
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
    skel = connection_tracker_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load BPF\n");
        return 1;
    }

    // Attach to cgroup
    cgroup_fd = attach_cgroup(
        bpf_program__fd(skel->progs.connection_tracker),
        cgroup_path);
    if (cgroup_fd < 0)
        goto cleanup;

    printf("Connection Tracker started\n");
    printf("Attached to cgroup: %s\n\n", cgroup_path);

    if (list_mode) {
        printf("Listing connections every 2 seconds...\n");
        while (!exiting) {
            print_connections(skel);
            sleep(2);
        }
    } else {
        printf("%12s %-11s %-16s CONNECTION\n", "TIME(s)", "EVENT", "PROCESS");

        rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
                               handle_event, &verbose, NULL);
        if (!rb) {
            fprintf(stderr, "Failed to create ring buffer\n");
            goto cleanup;
        }

        while (!exiting) {
            ring_buffer__poll(rb, 100);
        }
    }

    print_stats(skel);

cleanup:
    ring_buffer__free(rb);
    if (cgroup_fd >= 0) {
        bpf_prog_detach(cgroup_fd, BPF_CGROUP_SOCK_OPS);
        close(cgroup_fd);
    }
    connection_tracker_bpf__destroy(skel);

    printf("\nCleaned up\n");
    return 0;
}
```

## Step 4: Makefile

```makefile
CLANG ?= clang
BPFTOOL ?= bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

CFLAGS := -g -O2 -Wall
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)

LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LDFLAGS := $(shell pkg-config --libs libbpf 2>/dev/null || echo "-lbpf -lelf -lz")

all: connection_tracker

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

connection_tracker.bpf.o: connection_tracker.bpf.c connection_tracker.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

connection_tracker.skel.h: connection_tracker.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

connection_tracker: connection_tracker.c connection_tracker.skel.h connection_tracker.h
	$(CLANG) $(CFLAGS) $(LIBBPF_CFLAGS) $< $(LIBBPF_LDFLAGS) -o $@

clean:
	rm -f connection_tracker *.o *.skel.h vmlinux.h
```

## Testing

```bash
# Build
make

# Run in event mode
sudo ./connection_tracker

# Run in list mode
sudo ./connection_tracker -l

# Show RTT updates
sudo ./connection_tracker -v

# Test with connections
curl https://example.com &
python3 -m http.server 8080 &
curl http://localhost:8080 &
```

## Sample Output

```
Connection Tracker started
Attached to cgroup: /sys/fs/cgroup

       TIME(s) EVENT       PROCESS          CONNECTION
       0.001   CONNECT     curl             192.168.1.100:45678 -> 93.184.216.34:443
       0.045   ESTABLISHED curl             192.168.1.100:45678 -> 93.184.216.34:443
       0.123   CLOSE       curl             192.168.1.100:45678 -> 93.184.216.34:443
```

## Challenges

1. **IPv6 support**: Handle IPv6 connections.

2. **Per-process aggregation**: Show statistics per process.

3. **Latency histograms**: Build RTT distribution histograms.

4. **Connection duration**: Track how long connections are open.

5. **Export to Prometheus**: Expose metrics for monitoring.

## What's Next

In [Project 07: Traffic Monitor](../project07-traffic-monitor/index.md), you'll combine multiple program types for comprehensive traffic analysis.
