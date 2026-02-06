# Chapter 31: eBPF Security Model

Running code inside the kernel is inherently dangerous. A bug in a kernel module can crash the entire machine. eBPF exists because the kernel needed a way to let users run custom logic safely -- without the risks of traditional kernel modules.

The eBPF security model has two layers: the **verifier** (which ensures programs are safe) and **capabilities** (which control who can load programs in the first place). Think of it like a Python web application where you have both input validation (verifier) and authentication/authorization (capabilities). You need both.

## The Verifier as Sandbox

You met the verifier in Part 2. From a security perspective, the verifier is the most critical piece of the eBPF security model. It is a static analyzer that runs before your program is loaded into the kernel, and it rejects any program it cannot prove is safe.

The verifier guarantees:

- **No out-of-bounds memory access** -- every pointer dereference is checked
- **No infinite loops** -- all loops must have provable upper bounds
- **No uninitialized memory reads** -- stack variables must be written before being read
- **No invalid helper calls** -- only helpers available to the program type can be called
- **No unreachable code** -- dead code is rejected
- **Bounded execution time** -- programs must terminate within a fixed instruction count

```c
// The verifier rejects this: out-of-bounds access
SEC("xdp")
int bad_program(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // No bounds check -- verifier rejects this
    struct ethhdr *eth = data;
    __u16 proto = eth->h_proto;  // REJECTED: data might be shorter than ethhdr

    return XDP_PASS;
}

// The verifier accepts this: bounds checked
SEC("xdp")
int good_program(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;  // Packet too short, bail out

    __u16 proto = eth->h_proto;  // OK: verifier knows eth is within bounds
    return XDP_PASS;
}
```

!!! tip "Python Comparison"
    The verifier is like a very strict type checker -- imagine running `mypy` with every strictness option enabled, plus bounds checking, plus termination analysis. In Python, type errors are caught at runtime (or by optional tools like mypy). In eBPF, the verifier catches safety violations *before your code ever runs in the kernel*.

## Required Capabilities

Even if your program passes the verifier, you still need the right Linux capabilities to load it. Capabilities are the kernel's fine-grained permission system -- they replace the blunt "root or not root" model.

### Before Kernel 5.8: `CAP_SYS_ADMIN`

Before kernel 5.8, loading any eBPF program required `CAP_SYS_ADMIN` -- the most powerful capability in Linux. This was the equivalent of requiring full root access.

### Kernel 5.8+: Fine-Grained Capabilities

Kernel 5.8 introduced `CAP_BPF` and split eBPF operations across multiple capabilities:

| Capability | What It Allows | Typical Use |
|-----------|----------------|-------------|
| `CAP_BPF` | Load eBPF programs, create maps, access BTF | Base requirement for eBPF (since 5.8) |
| `CAP_NET_ADMIN` | Attach networking programs (XDP, TC, socket) | Network monitoring and packet manipulation |
| `CAP_PERFMON` | Attach tracing programs (kprobe, tracepoint, perf) | Observability and performance analysis |
| `CAP_SYS_ADMIN` | Full access including all BPF operations | Still required for some operations |

In practice, a tracing program needs `CAP_BPF + CAP_PERFMON`, and a network program needs `CAP_BPF + CAP_NET_ADMIN`:

```bash
# Run an XDP program with minimal capabilities (kernel 5.8+)
sudo capsh --caps="cap_bpf,cap_net_admin+eip" -- -c ./my_xdp_loader

# Run a kprobe tracer with minimal capabilities
sudo capsh --caps="cap_bpf,cap_perfmon+eip" -- -c ./my_tracer
```

=== "BCC (Python)"

    ```python
    #!/usr/bin/env python3
    """
    Check if we have the right capabilities before loading.
    BCC typically requires root, but we can check programmatically.
    """
    import os
    import sys

    def check_capabilities():
        """Read current process capabilities from /proc."""
        if os.geteuid() == 0:
            print("Running as root -- all capabilities available")
            return True

        try:
            with open("/proc/self/status", "r") as f:
                for line in f:
                    if line.startswith("CapEff:"):
                        cap_hex = int(line.split(":")[1].strip(), 16)
                        # CAP_BPF = 39, CAP_NET_ADMIN = 12, CAP_PERFMON = 38
                        has_bpf = bool(cap_hex & (1 << 39))
                        has_net = bool(cap_hex & (1 << 12))
                        has_perf = bool(cap_hex & (1 << 38))
                        print(f"CAP_BPF: {has_bpf}")
                        print(f"CAP_NET_ADMIN: {has_net}")
                        print(f"CAP_PERFMON: {has_perf}")
                        return has_bpf
        except IOError:
            pass
        return False

    if not check_capabilities():
        print("Insufficient capabilities for eBPF", file=sys.stderr)
        sys.exit(1)

    from bcc import BPF
    b = BPF(text=r"""
    int kprobe__do_sys_open(struct pt_regs *ctx) {
        bpf_trace_printk("open called\n");
        return 0;
    }
    """)
    b.trace_print()
    ```

=== "libbpf (C)"

    ```c
    /* check_caps.c -- Userspace loader that verifies capabilities */
    #include <stdio.h>
    #include <stdlib.h>
    #include <unistd.h>
    #include <sys/capability.h>
    #include <bpf/libbpf.h>
    #include "my_program.skel.h"

    static int check_cap(cap_value_t cap, const char *name) {
        cap_t caps = cap_get_proc();
        if (!caps) return 0;

        cap_flag_value_t val;
        cap_get_flag(caps, cap, CAP_EFFECTIVE, &val);
        cap_free(caps);

        printf("%s: %s\n", name, val == CAP_SET ? "yes" : "no");
        return val == CAP_SET;
    }

    int main(void) {
        if (geteuid() != 0) {
            /* Check individual capabilities */
            int has_bpf = check_cap(CAP_BPF, "CAP_BPF");
            int has_net = check_cap(CAP_NET_ADMIN, "CAP_NET_ADMIN");
            if (!has_bpf || !has_net) {
                fprintf(stderr, "Missing required capabilities\n");
                return 1;
            }
        }

        struct my_program *skel = my_program__open_and_load();
        if (!skel) {
            fprintf(stderr, "Failed to load BPF program\n");
            return 1;
        }

        /* ... attach and run ... */
        my_program__destroy(skel);
        return 0;
    }
    ```

## Unprivileged BPF

What can an unprivileged user (no root, no capabilities) do with BPF? Very little.

Unprivileged BPF is restricted to **classic BPF (cBPF) socket filters** -- the original packet filtering mechanism that predates eBPF. These programs can only:

- Attach to sockets the user owns
- Filter packets (read-only, no modification)
- Use a limited instruction set (cBPF, not eBPF)

!!! warning "Unprivileged eBPF Is Often Disabled Entirely"
    Many distributions disable unprivileged BPF by default for security reasons:

    ```bash
    # Check if unprivileged BPF is allowed
    cat /proc/sys/kernel/unprivileged_bpf_disabled

    # 0 = allowed, 1 = disabled (cannot be re-enabled without reboot)
    # 2 = disabled (can be re-enabled by writing 0)
    ```

    Setting this to `1` is a one-way switch -- once disabled, unprivileged BPF stays disabled until the next reboot. This prevents an attacker from re-enabling it after you lock it down.

## Attack Surface Considerations

Even with the verifier and capability checks, eBPF has an attack surface. Understanding it helps you reason about risk.

### Information Disclosure via Maps

BPF maps are shared between kernel and userspace. A program with map access can read sensitive kernel data:

```c
// An eBPF program could read kernel memory addresses,
// process credentials, network data, etc.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct sensitive_data);
} leaked_data SEC(".maps");
```

If the userspace component that reads this map is compromised, the attacker gets access to whatever the eBPF program collected. This is why map permissions and access control matter (covered in Chapter 34).

### Speculative Execution Side Channels

The eBPF JIT compiler generates native machine code that runs at full speed. Research has shown that eBPF programs could theoretically be used for Spectre-style side-channel attacks. The kernel mitigates this by:

- Inserting speculation barriers in JIT-compiled code
- Masking pointer arithmetic to prevent speculative out-of-bounds access
- Restricting unprivileged BPF access (the main defense)

### Verifier Bugs

The verifier itself is complex software, and bugs have been found in it. A verifier bug could allow a malicious program to bypass safety checks. Keeping your kernel up to date is the primary mitigation.

!!! danger "The Verifier Is Not Perfect"
    The verifier is remarkably effective, but it has had vulnerabilities (CVE-2021-3490, CVE-2022-23222, among others). Each was a case where the verifier's model of a program's behavior diverged from the actual runtime behavior. The defense-in-depth approach -- capabilities + verifier + kernel lockdown -- exists precisely because no single layer is bulletproof.

## Kernel Lockdown Mode

Linux kernel lockdown mode (enabled via `lockdown=integrity` or `lockdown=confidentiality` on the kernel command line) restricts operations that could compromise kernel integrity. Under lockdown:

- **Integrity mode**: BPF programs that write to kernel memory are restricted
- **Confidentiality mode**: BPF programs that read arbitrary kernel memory are also restricted

```bash
# Check current lockdown mode
cat /sys/kernel/security/lockdown
# [none] integrity confidentiality
```

Lockdown interacts with eBPF by restricting what even privileged users can do. In confidentiality mode, reading kernel memory through kprobes and BPF is restricted, which limits tracing capabilities.

## BPF Token (Kernel 6.9+)

Kernel 6.9 introduced **BPF tokens**, a mechanism for delegated BPF access. Instead of granting a process broad capabilities like `CAP_BPF`, you can create a token that grants specific BPF permissions.

The token is created by a privileged process and pinned to a BPF filesystem. An unprivileged process can then use the token to perform specific BPF operations without needing full capabilities.

```bash
# Mount a BPF filesystem with token delegation enabled
mount -t bpf bpffs /sys/fs/bpf -o delegate_cmds=prog_load,map_create

# Now a process with access to this mount can load BPF programs
# without CAP_BPF -- the mount acts as the authority
```

!!! note "BPF Tokens Are New"
    BPF tokens (kernel 6.9+, mid-2024) are still an emerging feature. The primary use case is container environments where you want to grant specific BPF abilities to a container without giving it broad capabilities. This is a significant improvement over the previous model where containers needed `CAP_SYS_ADMIN` or `CAP_BPF` to use eBPF at all.

## The Trust Model

Understanding who you trust is fundamental to eBPF security:

| Question | Consideration |
|----------|--------------|
| Who can load programs? | Controlled by capabilities and BPF tokens |
| Who can read/write maps? | Controlled by file permissions on pinned maps and fd passing |
| Who can attach to hooks? | Controlled by program type and attach-point-specific permissions |
| Who can inspect loaded programs? | Controlled by `CAP_SYS_ADMIN` or `CAP_BPF` (bpftool access) |
| Who compiled the program? | Not currently verified by the kernel (signing is emerging) |

!!! tip "Python Comparison"
    The eBPF trust model is like a deployment pipeline. In Python, you trust your CI/CD to run tests, your package manager to verify dependencies, and your runtime to enforce permissions. In eBPF, you trust the verifier to check safety, capabilities to control access, and kernel lockdown to limit scope. The weakest link in either chain determines your actual security.

## Summary

The eBPF security model is defense-in-depth:

1. **Capabilities** gate who can load programs
2. **The verifier** ensures programs are safe
3. **Program type restrictions** limit what programs can access
4. **Kernel lockdown** restricts even privileged operations
5. **BPF tokens** (6.9+) enable fine-grained delegation

No single layer is sufficient. Together, they make eBPF remarkably safe for running user-defined code in the kernel -- but you must understand each layer to deploy eBPF responsibly.

## Exercises

1. **Capability audit**: On a Linux system, read `/proc/self/status` and decode the `CapEff` field to determine which capabilities your current shell has. Write a Python script that checks for `CAP_BPF`, `CAP_NET_ADMIN`, and `CAP_PERFMON` and reports which eBPF program types you could load.

2. **Unprivileged BPF check**: Check the value of `/proc/sys/kernel/unprivileged_bpf_disabled` on your system. Research what your distribution sets this to by default and why. Try loading a simple eBPF program as an unprivileged user and observe the error.

3. **Lockdown investigation**: Check whether your kernel has lockdown enabled (`/sys/kernel/security/lockdown`). If it does, try loading a kprobe eBPF program and observe whether it succeeds. If lockdown is not enabled, research which distributions enable it by default.

4. **Capability comparison**: Write two shell scripts that load the same XDP program. One uses `sudo` (full root). The other uses `capsh` to grant only `CAP_BPF` and `CAP_NET_ADMIN`. Verify that both work, then try removing `CAP_NET_ADMIN` from the second script and observe the failure.

5. **Verifier escape research**: Look up CVE-2021-3490 or CVE-2022-23222. Write a brief summary of what the vulnerability was, how it was exploited, and how it was fixed. This exercise builds awareness that the verifier, while excellent, is not infallible.
