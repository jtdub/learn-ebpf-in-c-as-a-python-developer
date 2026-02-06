# Development Environment

Before writing any eBPF code, you need a Linux environment with the right kernel version and toolchain. eBPF programs run inside the Linux kernel — there's no macOS or Windows equivalent.

## Linux Kernel Requirements

eBPF features have been added progressively across kernel versions. For this guide, you need **kernel 5.8 or later** (ideally 5.15+) to access all program types and features we'll cover.

Check your kernel version:

```bash
uname -r
```

## Option 1: Native Linux

If you're already running Linux, you likely just need to install the toolchain packages. This is the simplest path.

### Ubuntu/Debian (22.04+)

```bash
sudo apt update
sudo apt install -y \
    clang \
    llvm \
    libbpf-dev \
    bpfcc-tools \
    linux-headers-$(uname -r) \
    linux-tools-common \
    linux-tools-$(uname -r) \
    python3-bpfcc \
    gcc \
    make \
    pkg-config \
    libelf-dev \
    zlib1g-dev
```

### Fedora (36+)

```bash
sudo dnf install -y \
    clang \
    llvm \
    libbpf-devel \
    bcc-tools \
    python3-bcc \
    kernel-devel \
    bpftool \
    gcc \
    make \
    elfutils-libelf-devel \
    zlib-devel
```

## Option 2: Virtual Machine

If you're on macOS or Windows, use a VM. This is the recommended approach for non-Linux hosts.

### Using Vagrant

```bash
# Install Vagrant and VirtualBox first, then:
mkdir ebpf-dev && cd ebpf-dev
vagrant init ubuntu/jammy64
vagrant up
vagrant ssh
```

Once inside the VM, run the Ubuntu package install commands above.

### Using Multipass (macOS)

```bash
brew install multipass
multipass launch --name ebpf-dev --cpus 2 --memory 4G --disk 20G jammy
multipass shell ebpf-dev
```

### Using Lima (macOS, lightweight)

```bash
brew install lima
limactl start --name=ebpf-dev template://ubuntu-lts
limactl shell ebpf-dev
```

## Option 3: Docker (Limited)

Docker can work for BCC-based development but has limitations for libbpf programs since the container shares the host kernel. You need `--privileged` mode and access to kernel headers.

```bash
docker run -it --privileged \
    -v /lib/modules:/lib/modules:ro \
    -v /usr/src:/usr/src:ro \
    -v /sys/kernel/debug:/sys/kernel/debug:ro \
    ubuntu:22.04 bash
```

Then install the packages inside the container. Note that XDP and some cgroup-based programs may not work correctly in Docker.

!!! warning "Docker Limitations"
    Docker shares the host kernel, so you can't control the kernel version. Some eBPF program types (especially cgroup hooks) behave differently in containers. For the full experience, use a VM.

## Verify Your Setup

### Check clang can target BPF

```bash
clang --version
# Should show clang 14+

echo '#include <linux/bpf.h>' | clang -target bpf -c -x c - -o /dev/null
# Should produce no errors
```

### Check bpftool is available

```bash
sudo bpftool version
# Should show bpftool version and libbpf version
```

### Check BCC Python bindings

```python
python3 -c "from bcc import BPF; print('BCC OK')"
```

### Check kernel BTF support (needed for CO-RE)

```bash
ls /sys/kernel/btf/vmlinux
# Should exist. If not, your kernel wasn't compiled with CONFIG_DEBUG_INFO_BTF=y
```

### Check available kernel headers

```bash
ls /usr/src/linux-headers-$(uname -r)/
# Should list kernel header files
```

## Project Directory Structure

Create a workspace for the projects in this guide:

```bash
mkdir -p ~/ebpf-learn/{src,projects}
cd ~/ebpf-learn
```

We'll use this directory throughout the guide. Each project will get its own subdirectory under `projects/`.

## Editor Setup

Any editor works, but C language support helps. If you use VS Code:

```bash
# Install the C/C++ extension for IntelliSense
code --install-extension ms-vscode.cpptools
```

For kernel header completions, add this to your VS Code `settings.json`:

```json
{
    "C_Cpp.default.includePath": [
        "/usr/include",
        "/usr/src/linux-headers-*/include",
        "/usr/src/linux-headers-*/arch/x86/include"
    ]
}
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `bpftool: command not found` | Install `linux-tools-common` and `linux-tools-$(uname -r)` |
| `No such file: /sys/kernel/btf/vmlinux` | Your kernel lacks BTF support. Use a newer kernel or enable `CONFIG_DEBUG_INFO_BTF` |
| `Operation not permitted` when loading BPF | Run with `sudo` or set `CAP_BPF` capability |
| `Cannot find linux headers` | Install `linux-headers-$(uname -r)` |
| BCC import fails | Install `python3-bpfcc` (Ubuntu) or `python3-bcc` (Fedora) |
