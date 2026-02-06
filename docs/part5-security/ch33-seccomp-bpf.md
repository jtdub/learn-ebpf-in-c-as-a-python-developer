# Chapter 33: Seccomp-BPF

Seccomp (Secure Computing Mode) filters system calls for a process. Combined with BPF, it provides fine-grained syscall filtering — essential for sandboxing applications like containers, browsers, and untrusted code.

## Seccomp Modes

| Mode | Description |
|------|-------------|
| Strict | Only `read`, `write`, `exit`, `sigreturn` allowed |
| Filter (BPF) | Custom syscall filtering with BPF |

## How Seccomp-BPF Works

```
Process makes syscall
       │
       ▼
┌─────────────────────┐
│  Seccomp Filter     │
│  (cBPF program)     │
│                     │
│  if (syscall == X)  │
│    return KILL      │
│  else               │
│    return ALLOW     │
└─────────────────────┘
       │
       ▼
  Kernel executes (or kills process)
```

!!! note "cBPF, not eBPF"
    Seccomp uses classic BPF (cBPF), not extended BPF (eBPF). The program format is simpler but more limited.

## Seccomp Filter Data

The filter receives a `struct seccomp_data`:

```c
struct seccomp_data {
    int   nr;                    // Syscall number
    __u32 arch;                  // Architecture
    __u64 instruction_pointer;   // IP at time of syscall
    __u64 args[6];               // Syscall arguments
};
```

## Return Actions

| Action | Effect |
|--------|--------|
| `SECCOMP_RET_ALLOW` | Allow syscall |
| `SECCOMP_RET_KILL_PROCESS` | Kill the process |
| `SECCOMP_RET_KILL_THREAD` | Kill the thread |
| `SECCOMP_RET_TRAP` | Send SIGSYS signal |
| `SECCOMP_RET_ERRNO` | Return error to caller |
| `SECCOMP_RET_TRACE` | Notify ptrace tracer |
| `SECCOMP_RET_LOG` | Allow but log |
| `SECCOMP_RET_USER_NOTIF` | Notify userspace (5.0+) |

## Writing Seccomp Filters

### Using libseccomp (High-Level)

```c
#include <seccomp.h>
#include <stdio.h>
#include <unistd.h>

int main() {
    // Create filter context (default: kill on unknown syscall)
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);

    // Allow basic syscalls
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

    // Allow write() only to stdout (fd=1)
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
                     SCMP_A0(SCMP_CMP_EQ, 1));

    // Load the filter
    seccomp_load(ctx);

    // Now restricted
    printf("This works (stdout)\n");

    // This would be killed:
    // open("/etc/passwd", O_RDONLY);

    seccomp_release(ctx);
    return 0;
}
```

Compile:

```bash
gcc -o sandbox sandbox.c -lseccomp
```

### Using Raw BPF

For understanding, here's raw BPF:

```c
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <sys/prctl.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

int main() {
    struct sock_filter filter[] = {
        // Load architecture
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, arch)),
        // Check architecture (x86_64)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),

        // Load syscall number
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, nr)),

        // Allow read (0)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_read, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

        // Allow write (1)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_write, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

        // Allow exit_group (231)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_exit_group, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

        // Kill on anything else
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
    };

    struct sock_fprog prog = {
        .len = sizeof(filter) / sizeof(filter[0]),
        .filter = filter,
    };

    // Enable no-new-privs (required)
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

    // Install filter
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);

    // Test
    printf("Allowed!\n");

    return 0;
}
```

## Python Integration

### Using pyseccomp

```python
#!/usr/bin/env python3
import seccomp

# Default: kill
f = seccomp.SyscallFilter(defaction=seccomp.KILL)

# Allow essential syscalls
f.add_rule(seccomp.ALLOW, "read")
f.add_rule(seccomp.ALLOW, "write")
f.add_rule(seccomp.ALLOW, "close")
f.add_rule(seccomp.ALLOW, "fstat")
f.add_rule(seccomp.ALLOW, "mmap")
f.add_rule(seccomp.ALLOW, "mprotect")
f.add_rule(seccomp.ALLOW, "munmap")
f.add_rule(seccomp.ALLOW, "brk")
f.add_rule(seccomp.ALLOW, "exit_group")

# Conditional: only allow write to stdout
f.add_rule(seccomp.ALLOW, "write",
           seccomp.Arg(0, seccomp.EQ, 1))  # fd == 1

# Load filter
f.load()

# Now sandboxed
print("This works!")
```

### Generating Filters from BCC

While seccomp uses cBPF, you can generate filters programmatically:

```python
#!/usr/bin/env python3
"""Generate seccomp filter based on observed syscalls."""
from bcc import BPF
import seccomp
import sys

# First, trace what syscalls a program uses
tracer = r"""
BPF_HASH(syscalls, u32, u64);

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u32 nr = args->id;
    u64 *count = syscalls.lookup_or_try_init(&nr, &(u64){0});
    if (count) (*count)++;
    return 0;
}
"""

def trace_syscalls(command, duration=5):
    """Run command and collect syscall numbers."""
    b = BPF(text=tracer)
    # ... trace for duration ...
    return [k.value for k in b["syscalls"].keys()]

def generate_filter(syscalls):
    """Generate seccomp filter allowing only these syscalls."""
    f = seccomp.SyscallFilter(defaction=seccomp.ERRNO(seccomp.errno.EPERM))

    for nr in syscalls:
        try:
            name = seccomp.resolve_syscall(seccomp.Arch.NATIVE, nr)
            f.add_rule(seccomp.ALLOW, name)
        except:
            pass  # Unknown syscall

    return f
```

## Seccomp User Notification

Kernel 5.0+ allows delegating decisions to userspace:

```c
// In the sandboxed process
struct sock_filter filter[] = {
    // For open(), notify userspace instead of allowing
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
    // ...
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
};
```

```c
// Supervisor process receives notifications
int notify_fd = seccomp(SECCOMP_SET_MODE_FILTER,
                        SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);

struct seccomp_notif *req = malloc(sizeof(*req));
struct seccomp_notif_resp *resp = malloc(sizeof(*resp));

while (1) {
    ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_RECV, req);

    // Examine request
    printf("PID %d wants syscall %d\n", req->pid, req->data.nr);

    // Respond
    resp->id = req->id;
    resp->val = 0;           // Return value
    resp->error = -EPERM;    // Or 0 for success
    resp->flags = 0;

    ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, resp);
}
```

## Container Seccomp Profiles

Docker and Kubernetes use seccomp profiles:

```json
{
    "defaultAction": "SCMP_ACT_ERRNO",
    "architectures": ["SCMP_ARCH_X86_64"],
    "syscalls": [
        {
            "names": ["read", "write", "close", "fstat"],
            "action": "SCMP_ACT_ALLOW"
        },
        {
            "names": ["clone"],
            "action": "SCMP_ACT_ALLOW",
            "args": [
                {
                    "index": 0,
                    "value": 2114060288,
                    "op": "SCMP_CMP_MASKED_EQ"
                }
            ]
        }
    ]
}
```

Apply in Docker:

```bash
docker run --security-opt seccomp=profile.json myimage
```

## Common Sandbox Patterns

### Minimal (Read/Write Only)

```c
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
```

### Network Server

```c
// Basic ops
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);

// Networking
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(bind), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(listen), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(accept), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(accept4), 0);

// Polling
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_create1), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_ctl), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_wait), 0);

// Block dangerous
seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(ptrace), 0);
```

### No Network

```c
// Block all network syscalls
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(socket), 0);
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(connect), 0);
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(accept), 0);
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(bind), 0);
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(listen), 0);
```

## Debugging Seccomp

### Audit Mode

Log blocked syscalls instead of killing:

```c
seccomp_init(SCMP_ACT_LOG);  // Log everything
// Or for specific syscalls:
seccomp_rule_add(ctx, SCMP_ACT_LOG, SCMP_SYS(open), 0);
```

View in audit log:

```bash
sudo ausearch -m SECCOMP
```

### Using strace

```bash
# Show seccomp filter
strace -e trace=seccomp ./sandbox

# Show denied syscalls
strace -f ./sandbox 2>&1 | grep -i "operation not permitted"
```

### Using perf

```bash
sudo perf trace -e 'syscalls:*' ./sandbox
```

## Seccomp vs eBPF LSM

| Feature | Seccomp-BPF | eBPF LSM |
|---------|-------------|----------|
| Scope | Per-process | System-wide |
| BPF Type | Classic BPF | Extended BPF |
| Capabilities | Syscall filtering | All security hooks |
| Maps | No | Yes |
| Complexity | Simple | Complex |
| Kernel Version | 3.5+ | 5.7+ |

Use seccomp for per-process sandboxing, LSM for system policies.

## Exercises

1. **Basic sandbox**: Create a seccomp filter that allows only read, write, and exit.

2. **Python sandbox**: Sandbox a Python script to prevent file system access.

3. **Network-only**: Allow network syscalls but deny file system access.

4. **Audit mode**: Create a filter that logs (not kills) unexpected syscalls.

5. **Container profile**: Create a minimal seccomp profile for a web server container.

6. **User notification**: Implement a supervisor that handles blocked syscalls via user notification.
