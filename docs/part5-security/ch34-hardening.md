# Chapter 34: Hardening eBPF Deployments

Security isn't just what eBPF enforces — it's also how you deploy and manage eBPF programs securely. This chapter covers best practices for hardening eBPF infrastructure.

## The eBPF Attack Surface

```
┌─────────────────────────────────────────┐
│              User Space                  │
├─────────────────────────────────────────┤
│  bpf() syscall  │  Program loading       │ ← Attack vector 1
├─────────────────────────────────────────┤
│  Kernel         │  eBPF Verifier         │ ← Attack vector 2
├─────────────────────────────────────────┤
│  Kernel         │  eBPF Runtime          │ ← Attack vector 3
├─────────────────────────────────────────┤
│  Maps           │  Shared state          │ ← Attack vector 4
└─────────────────────────────────────────┘
```

## Capability Requirements

### Required Capabilities

| Capability | Purpose |
|------------|---------|
| `CAP_BPF` | Load and manage BPF programs (5.8+) |
| `CAP_PERFMON` | Attach to perf events, tracepoints |
| `CAP_NET_ADMIN` | Network programs (XDP, TC) |
| `CAP_SYS_ADMIN` | Legacy (pre-5.8) or privileged ops |

### Dropping Privileges

```c
#include <sys/capability.h>
#include <unistd.h>

void drop_caps_after_load(void) {
    cap_t caps = cap_get_proc();

    // Clear all capabilities
    cap_clear(caps);

    // Keep only what we need for ongoing operation
    cap_value_t keep[] = {CAP_PERFMON};  // For polling maps
    cap_set_flag(caps, CAP_PERMITTED, 1, keep, CAP_SET);
    cap_set_flag(caps, CAP_EFFECTIVE, 1, keep, CAP_SET);

    cap_set_proc(caps);
    cap_free(caps);
}
```

In Python:

```python
#!/usr/bin/env python3
import os
import ctypes

# After loading BPF, drop to unprivileged
def drop_privileges(uid, gid):
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)

# Load BPF as root, then drop
from bcc import BPF
b = BPF(text="...")  # Load requires CAP_BPF

drop_privileges(1000, 1000)  # Drop to user
# Now running unprivileged but BPF program stays attached
```

## Unprivileged BPF

### Checking System State

```bash
# Check if unprivileged BPF is allowed
cat /proc/sys/kernel/unprivileged_bpf_disabled
# 0 = allowed (less secure)
# 1 = disabled (recommended)
# 2 = permanently disabled
```

### Disabling Unprivileged BPF

```bash
# Temporary (until reboot)
echo 1 | sudo tee /proc/sys/kernel/unprivileged_bpf_disabled

# Permanent (add to sysctl.conf)
echo "kernel.unprivileged_bpf_disabled=1" | sudo tee -a /etc/sysctl.conf
```

!!! warning "Production Systems"
    Always disable unprivileged BPF in production. An attacker with local access could use BPF to probe the system.

## Program Signing

### Signing eBPF Programs

```bash
# Generate key pair
openssl genrsa -out bpf_private.pem 2048
openssl rsa -in bpf_private.pem -pubout -out bpf_public.pem

# Sign the BPF object file
openssl dgst -sha256 -sign bpf_private.pem -out prog.sig prog.bpf.o

# Verify before loading
openssl dgst -sha256 -verify bpf_public.pem -signature prog.sig prog.bpf.o
```

### Verification in Loader

```c
#include <openssl/evp.h>
#include <openssl/pem.h>

int verify_bpf_signature(const char *prog_path, const char *sig_path,
                          const char *pubkey_path) {
    FILE *pubkey_file = fopen(pubkey_path, "r");
    EVP_PKEY *pubkey = PEM_read_PUBKEY(pubkey_file, NULL, NULL, NULL);
    fclose(pubkey_file);

    // Read program
    FILE *prog_file = fopen(prog_path, "rb");
    fseek(prog_file, 0, SEEK_END);
    size_t prog_len = ftell(prog_file);
    fseek(prog_file, 0, SEEK_SET);
    unsigned char *prog_data = malloc(prog_len);
    fread(prog_data, 1, prog_len, prog_file);
    fclose(prog_file);

    // Read signature
    FILE *sig_file = fopen(sig_path, "rb");
    fseek(sig_file, 0, SEEK_END);
    size_t sig_len = ftell(sig_file);
    fseek(sig_file, 0, SEEK_SET);
    unsigned char *sig_data = malloc(sig_len);
    fread(sig_data, 1, sig_len, sig_file);
    fclose(sig_file);

    // Verify
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pubkey);
    EVP_DigestVerifyUpdate(ctx, prog_data, prog_len);
    int result = EVP_DigestVerifyFinal(ctx, sig_data, sig_len);

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pubkey);
    free(prog_data);
    free(sig_data);

    return result == 1;  // 1 = valid
}
```

## Map Security

### Restricting Map Access

```c
// Create map accessible only by root
int create_secure_map(void) {
    union bpf_attr attr = {
        .map_type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(__u32),
        .value_size = sizeof(__u64),
        .max_entries = 1024,
        .map_flags = 0,  // No special flags
    };

    int fd = syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));

    // Pin with restricted permissions
    chmod("/sys/fs/bpf/my_map", 0600);  // Owner only

    return fd;
}
```

### Pinning with Proper Permissions

```bash
# Create restricted BPF filesystem mount
sudo mkdir -p /sys/fs/bpf/secure
sudo mount -t bpf none /sys/fs/bpf/secure -o mode=0700

# Only root can access programs pinned here
```

### Map Data Validation

```c
SEC("kprobe/__x64_sys_execve")
int trace_exec(struct pt_regs *ctx) {
    __u32 key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &key);

    if (!cfg)
        return 0;

    // CRITICAL: Validate map data before use
    if (cfg->max_args > MAX_ALLOWED_ARGS)
        cfg->max_args = MAX_ALLOWED_ARGS;

    if (cfg->path_len > PATH_MAX)
        cfg->path_len = PATH_MAX;

    // Now safe to use
    // ...
    return 0;
}
```

## Verifier Hardening

### Understanding Verifier Limits

```bash
# Check verifier complexity limit
cat /proc/sys/kernel/bpf_jit_limit

# Check JIT status
cat /proc/sys/net/core/bpf_jit_enable
# 0 = interpreter only (slower but auditable)
# 1 = JIT enabled
# 2 = JIT enabled + debug output
```

### Hardening JIT

```bash
# Enable JIT hardening (constant blinding)
echo 1 | sudo tee /proc/sys/net/core/bpf_jit_harden

# 0 = disabled
# 1 = enabled for unprivileged
# 2 = enabled for all
```

!!! note "Constant Blinding"
    JIT hardening blinds constants to prevent JIT spraying attacks. This adds overhead but improves security.

## Audit and Monitoring

### Logging BPF Operations

Create an eBPF program to monitor eBPF:

```c
// audit_bpf.bpf.c
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct event {
    __u32 pid;
    __u32 uid;
    __u32 cmd;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_bpf")
int audit_bpf(struct trace_event_raw_sys_enter *ctx) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->cmd = ctx->args[0];  // BPF command
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

BPF commands to watch:

| Command | Value | Meaning |
|---------|-------|---------|
| `BPF_MAP_CREATE` | 0 | Creating new map |
| `BPF_PROG_LOAD` | 5 | Loading new program |
| `BPF_PROG_ATTACH` | 8 | Attaching program |
| `BPF_LINK_CREATE` | 28 | Creating link |

### Integration with Audit Framework

```bash
# Add audit rules for bpf syscall
sudo auditctl -a always,exit -F arch=b64 -S bpf -k bpf_activity

# View audit logs
sudo ausearch -k bpf_activity
```

## Resource Limits

### Memory Limits

```c
// Set memory limit for BPF subsystem
struct rlimit rl = {
    .rlim_cur = 64 * 1024 * 1024,  // 64 MB soft
    .rlim_max = 64 * 1024 * 1024,  // 64 MB hard
};
setrlimit(RLIMIT_MEMLOCK, &rl);
```

System-wide limits:

```bash
# Check current BPF memory usage
cat /proc/meminfo | grep -i bpf

# Limit total BPF memory (cgroup v2)
echo "100M" > /sys/fs/cgroup/user.slice/memory.max
```

### Program Complexity Limits

```bash
# Check verifier instruction limit
# Default: 1 million instructions (4096 for unprivileged)
cat /proc/sys/kernel/bpf_stats_enabled
```

## Secure Loader Patterns

### Minimal Loader

```c
// secure_loader.c - Load with minimal attack surface
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <unistd.h>
#include <pwd.h>

int main(int argc, char **argv) {
    // 1. Verify we're running as expected user
    if (geteuid() != 0) {
        fprintf(stderr, "Must run as root to load\n");
        return 1;
    }

    // 2. Set resource limits
    struct rlimit rl = {.rlim_cur = 10 * 1024 * 1024,
                        .rlim_max = 10 * 1024 * 1024};
    setrlimit(RLIMIT_MEMLOCK, &rl);

    // 3. Verify program signature
    if (!verify_signature(argv[1])) {
        fprintf(stderr, "Invalid signature\n");
        return 1;
    }

    // 4. Load program
    struct bpf_object *obj = bpf_object__open(argv[1]);
    bpf_object__load(obj);

    // 5. Attach
    // ...

    // 6. Pin for persistence
    bpf_object__pin(obj, "/sys/fs/bpf/secure/prog");

    // 7. Drop privileges
    struct passwd *nobody = getpwnam("nobody");
    setgid(nobody->pw_gid);
    setuid(nobody->pw_uid);

    // 8. Run event loop unprivileged
    while (1) {
        // Poll maps, handle events
        sleep(1);
    }

    return 0;
}
```

### Using systemd

```ini
# /etc/systemd/system/ebpf-agent.service
[Unit]
Description=eBPF Security Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ebpf-agent
# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_NET_ADMIN
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_NET_ADMIN
# Run as dedicated user after loading
User=ebpf-agent
Group=ebpf-agent
# Limit resources
MemoryMax=256M
CPUQuota=50%

[Install]
WantedBy=multi-user.target
```

## Network Security

### Protecting XDP Programs

```c
// Prevent unauthorized detachment
SEC("xdp")
int secure_xdp(struct xdp_md *ctx) {
    // Rate limit program replacements
    __u32 key = 0;
    __u64 *last_attach = bpf_map_lookup_elem(&state_map, &key);
    __u64 now = bpf_ktime_get_ns();

    if (last_attach && (now - *last_attach) < 60000000000ULL) {
        // Less than 60 seconds since last attach
        // Log suspicious activity
    }

    // ... normal processing ...
    return XDP_PASS;
}
```

### Watchdog Pattern

```python
#!/usr/bin/env python3
"""Watchdog to ensure critical BPF programs stay attached."""
import subprocess
import time
import sys

CRITICAL_PROGRAMS = [
    "/sys/fs/bpf/security/lsm_file_open",
    "/sys/fs/bpf/security/lsm_bprm_check",
]

def check_programs():
    for path in CRITICAL_PROGRAMS:
        result = subprocess.run(
            ["bpftool", "prog", "show", "pinned", path],
            capture_output=True
        )
        if result.returncode != 0:
            alert(f"Critical program missing: {path}")
            reload_program(path)

def alert(message):
    # Send to monitoring system
    print(f"ALERT: {message}", file=sys.stderr)
    # syslog, email, PagerDuty, etc.

def reload_program(path):
    # Reload from known-good source
    pass

while True:
    check_programs()
    time.sleep(10)
```

## Incident Response

### Listing Active Programs

```bash
#!/bin/bash
# inventory.sh - Inventory all BPF activity

echo "=== Loaded Programs ==="
bpftool prog list

echo -e "\n=== Maps ==="
bpftool map list

echo -e "\n=== Links ==="
bpftool link list

echo -e "\n=== Pinned Objects ==="
find /sys/fs/bpf -type f 2>/dev/null

echo -e "\n=== Network Attachments ==="
for iface in $(ip link show | grep -oP '^\d+: \K[^:@]+'); do
    echo "Interface: $iface"
    bpftool net show dev $iface 2>/dev/null
done
```

### Emergency Removal

```bash
#!/bin/bash
# emergency_remove.sh - Remove suspicious BPF programs

# Detach all XDP programs
for iface in $(ip link show | grep -oP '^\d+: \K[^:@]+'); do
    ip link set $iface xdp off 2>/dev/null
done

# Remove TC programs
for iface in $(ip link show | grep -oP '^\d+: \K[^:@]+'); do
    tc qdisc del dev $iface clsact 2>/dev/null
done

# Unpin all
find /sys/fs/bpf -type f -delete 2>/dev/null

# Note: Some programs (tracepoints, kprobes) will persist
# until their loader process exits
echo "Detached network programs. Restart services to clear others."
```

## Security Checklist

### Deployment

- [ ] Disable unprivileged BPF
- [ ] Enable JIT hardening
- [ ] Use capabilities instead of root
- [ ] Sign BPF programs
- [ ] Restrict map permissions
- [ ] Set memory limits
- [ ] Pin to restricted filesystem

### Monitoring

- [ ] Audit bpf() syscall
- [ ] Monitor for unauthorized programs
- [ ] Log map access patterns
- [ ] Track program attachment/detachment
- [ ] Alert on verifier failures

### Operations

- [ ] Document all deployed programs
- [ ] Version control BPF source
- [ ] Test programs in staging
- [ ] Have rollback procedures
- [ ] Regular security audits

## Exercises

1. **Capability dropping**: Write a loader that drops to minimal capabilities after loading.

2. **BPF auditing**: Create an eBPF program that logs all bpf() syscalls with details.

3. **Signed loading**: Implement a loader that verifies program signatures before loading.

4. **Watchdog**: Build a watchdog service that monitors critical BPF programs.

5. **Resource limits**: Configure a system with strict BPF resource limits using cgroups.

6. **Incident response**: Create a script that inventories all BPF activity and identifies unknown programs.
