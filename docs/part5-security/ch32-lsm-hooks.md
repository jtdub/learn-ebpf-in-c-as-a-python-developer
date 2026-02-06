# Chapter 32: LSM Hooks

Linux Security Modules (LSM) provide hooks throughout the kernel for security decisions. eBPF can attach to these hooks, allowing you to implement custom security policies without modifying the kernel.

## What is LSM?

LSM is a framework that lets security modules (like SELinux, AppArmor, or your eBPF program) intercept security-sensitive operations:

```
Application
    │
    ▼ (syscall)
┌─────────────────────────┐
│     Kernel Core         │
│   ┌───────────────┐     │
│   │ LSM Hook      │ ────┼──▶ SELinux
│   │ security_*()  │ ────┼──▶ AppArmor
│   │               │ ────┼──▶ Your eBPF program
│   └───────────────┘     │
└─────────────────────────┘
```

## BPF LSM Requirements

- Kernel 5.7+ (BPF LSM support)
- `CONFIG_BPF_LSM=y` in kernel config
- Boot with `lsm=...,bpf` parameter

Check if enabled:

```bash
cat /sys/kernel/security/lsm
# Should include "bpf"
```

Enable if needed:

```bash
# Add to boot parameters (GRUB)
GRUB_CMDLINE_LINUX="lsm=lockdown,capability,yama,bpf"
sudo update-grub
```

## LSM Program Basics

### SEC Naming

```c
SEC("lsm/bprm_check_security")
SEC("lsm/file_open")
SEC("lsm/socket_connect")
```

### Return Values

```c
return 0;      // Allow operation
return -EPERM; // Deny with "Permission denied"
return -EACCES; // Deny with "Access denied"
```

### Program Structure

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

SEC("lsm/file_open")
int BPF_PROG(file_open_check, struct file *file) {
    // Your security logic
    return 0;  // Allow
}
```

## Finding LSM Hooks

List available hooks:

```bash
# From kernel source
grep -r "security_.*(" include/linux/security.h

# Or check BTF
bpftool btf dump file /sys/kernel/btf/vmlinux | grep "security_"
```

Common hooks:

| Hook | When Called |
|------|-------------|
| `bprm_check_security` | Before executing a program |
| `file_open` | Opening a file |
| `file_permission` | File access check |
| `socket_connect` | Before connect() |
| `socket_bind` | Before bind() |
| `task_alloc` | Creating a new task |
| `task_fix_setuid` | setuid() calls |
| `mmap_file` | Memory mapping a file |

## Example: Block Executable

Prevent specific programs from running:

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// Blocked program (e.g., /usr/bin/wget)
#define BLOCKED_COMM "wget"

SEC("lsm/bprm_check_security")
int BPF_PROG(block_exec, struct linux_binprm *bprm) {
    char comm[16];

    // Get filename being executed
    const char *filename = BPF_CORE_READ(bprm, filename);
    bpf_probe_read_kernel_str(comm, sizeof(comm), filename);

    // Simple check - block if name contains "wget"
    // In production, check full path
    if (comm[0] == 'w' && comm[1] == 'g' && comm[2] == 'e' && comm[3] == 't')
        return -EPERM;

    return 0;
}
```

## Example: Network Access Control

Restrict which programs can make network connections:

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// Map of allowed programs (by inode)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);    // Inode number
    __type(value, __u8);   // 1 = allowed
} allowed_network SEC(".maps");

SEC("lsm/socket_connect")
int BPF_PROG(check_connect, struct socket *sock,
             struct sockaddr *address, int addrlen) {
    // Only check internet sockets
    __u16 family = BPF_CORE_READ(address, sa_family);
    if (family != AF_INET && family != AF_INET6)
        return 0;

    // Get current executable's inode
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct file *exe_file = BPF_CORE_READ(task, mm, exe_file);
    __u64 inode = BPF_CORE_READ(exe_file, f_inode, i_ino);

    // Check allowlist
    __u8 *allowed = bpf_map_lookup_elem(&allowed_network, &inode);
    if (!allowed)
        return -EPERM;  // Not in allowlist, deny

    return 0;
}
```

Populate the map from userspace:

```python
import os
import stat

# Get inode of allowed program
st = os.stat("/usr/bin/curl")
inode = st.st_ino

# Add to map
b["allowed_network"][inode] = 1
```

## Example: File Access Control

Protect sensitive files:

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// Protected directory inode (e.g., /etc/secrets)
#define PROTECTED_DIR_INODE 12345678

SEC("lsm/file_open")
int BPF_PROG(protect_files, struct file *file) {
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    struct inode *parent_inode = BPF_CORE_READ(file, f_path.dentry, d_parent, d_inode);

    // Check if file is in protected directory
    __u64 parent_ino = BPF_CORE_READ(parent_inode, i_ino);
    if (parent_ino == PROTECTED_DIR_INODE) {
        // Only allow root
        __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        if (uid != 0)
            return -EACCES;
    }

    return 0;
}
```

## Example: Setuid Protection

Monitor or restrict setuid operations:

```c
SEC("lsm/task_fix_setuid")
int BPF_PROG(check_setuid, struct cred *new, const struct cred *old, int flags) {
    __u32 old_uid = BPF_CORE_READ(old, uid.val);
    __u32 new_uid = BPF_CORE_READ(new, uid.val);

    // Log privilege escalation (non-root to root)
    if (old_uid != 0 && new_uid == 0) {
        bpf_printk("setuid escalation: %d -> %d\n", old_uid, new_uid);

        // Could deny here:
        // return -EPERM;
    }

    return 0;
}
```

## Example: Container Escape Prevention

Prevent processes from escaping namespaces:

```c
SEC("lsm/task_alloc")
int BPF_PROG(check_task_alloc, struct task_struct *task,
             unsigned long clone_flags) {
    // Check for namespace changes
    if (clone_flags & (CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET)) {
        // Get current namespace context
        struct task_struct *current = (void *)bpf_get_current_task();
        __u32 current_ns = BPF_CORE_READ(current, nsproxy, pid_ns_for_children, ns.inum);

        // If in container namespace, deny namespace operations
        // (In practice, compare against host namespace ID)
        if (current_ns != 0xF0000000) {  // Example host ns ID
            return -EPERM;
        }
    }

    return 0;
}
```

## Loading LSM Programs

### Using libbpf

```c
// lsm_loader.c
#include <stdio.h>
#include <bpf/libbpf.h>
#include "lsm_policy.skel.h"

int main() {
    struct lsm_policy_bpf *skel;

    skel = lsm_policy_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load LSM program\n");
        return 1;
    }

    // LSM programs auto-attach via skeleton
    if (lsm_policy_bpf__attach(skel)) {
        fprintf(stderr, "Failed to attach\n");
        return 1;
    }

    printf("LSM policy active. Press Ctrl+C to exit.\n");

    // Keep running
    while (1)
        sleep(1);

    lsm_policy_bpf__destroy(skel);
    return 0;
}
```

### Using bpftool

```bash
# Load
sudo bpftool prog load lsm_policy.bpf.o /sys/fs/bpf/lsm_policy type lsm

# Verify
sudo bpftool prog list | grep lsm
```

## Combining Multiple Hooks

Create comprehensive policies:

```c
// Block dangerous operations

SEC("lsm/bprm_check_security")
int BPF_PROG(block_dangerous_exec, struct linux_binprm *bprm) {
    // Block certain executables
    return check_exec_allowed(bprm);
}

SEC("lsm/file_permission")
int BPF_PROG(protect_files, struct file *file, int mask) {
    // Protect sensitive files
    return check_file_access(file, mask);
}

SEC("lsm/socket_connect")
int BPF_PROG(control_network, struct socket *sock,
             struct sockaddr *address, int addrlen) {
    // Control network access
    return check_network_allowed(sock, address);
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(block_ptrace, struct task_struct *child, unsigned int mode) {
    // Prevent debugging
    return -EPERM;  // Block all ptrace
}
```

## Debugging LSM Programs

### Check Attachment

```bash
# List LSM programs
sudo bpftool prog list type lsm

# Check if specific hook is used
sudo cat /sys/kernel/debug/tracing/trace_pipe
# (With bpf_printk in your program)
```

### Testing

```bash
# Test in isolated namespace
unshare --user --map-root-user --mount-proc --fork /bin/bash

# Try blocked operation
wget http://example.com  # Should fail if blocked
```

## Security Considerations

1. **Performance**: LSM hooks are in critical paths. Keep logic minimal.

2. **Bypass**: Ensure complete coverage. Blocking `socket_connect` doesn't block raw sockets.

3. **Denial of Service**: A buggy LSM program can break the system. Test thoroughly.

4. **Privilege**: Loading LSM programs requires CAP_SYS_ADMIN.

5. **Stacking**: BPF LSM runs alongside other LSMs. A deny from any LSM blocks the operation.

## Exercises

1. **Process allowlist**: Create an LSM that only allows specific processes to run.

2. **Network egress control**: Block all outbound connections except to allowed IP addresses.

3. **File integrity**: Prevent modification of files in /etc.

4. **Privilege tracking**: Log all setuid/setgid operations.

5. **Container hardening**: Block namespace creation for non-root containers.

6. **Memory protection**: Prevent executable memory mappings (W^X enforcement).
