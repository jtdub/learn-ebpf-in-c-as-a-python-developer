# Chapter 1: Types & Variables

In Python, you rarely think about types. You write `x = 42` and Python figures out that `x` is an integer. You write `x = "hello"` and now it's a string. The variable `x` is just a name — a label that can point to any object at any time.

C does not work this way. In C, every variable has a fixed type declared at compile time, and that type determines exactly how many bytes the variable occupies in memory. You cannot change a variable's type after declaration. This is the first fundamental shift.

## Python Types vs C Types

=== "Python"

    ```python
    # Python figures out the types for you
    x = 42            # int (arbitrary precision)
    y = 3.14          # float (64-bit double)
    c = 'A'           # str (no separate char type)
    flag = True       # bool
    name = "hello"    # str (Unicode, variable length)
    ```

=== "C"

    ```c
    // You must declare the type explicitly
    int x = 42;            // 32-bit signed integer
    double y = 3.14;       // 64-bit floating point
    char c = 'A';          // 8-bit character (actually a small integer)
    int flag = 1;          // No built-in bool in older C (use 0/1)
    char name[] = "hello"; // Array of bytes, null-terminated
    ```

!!! note "Semicolons and Declarations"
    Every statement in C ends with a semicolon. Every variable must be declared with its type before use. If you forget the type, the compiler rejects your code — there is no runtime to figure it out.

## Integer Types and Their Sizes

This is where C gets specific in a way Python never does. In Python, `int` has arbitrary precision — it can be as large as your memory allows. In C, integers have fixed sizes:

| C Type | Size | Range | Python Equivalent |
|--------|------|-------|-------------------|
| `char` | 1 byte | -128 to 127 | N/A (Python has no char) |
| `short` | 2 bytes | -32,768 to 32,767 | N/A |
| `int` | 4 bytes | -2,147,483,648 to 2,147,483,647 | `int` (but Python's is unbounded) |
| `long` | 4 or 8 bytes | Platform-dependent | `int` |
| `long long` | 8 bytes | -9.2 * 10^18 to 9.2 * 10^18 | `int` |
| `float` | 4 bytes | ~7 decimal digits precision | N/A |
| `double` | 8 bytes | ~15 decimal digits precision | `float` |

### Signed vs Unsigned

Every integer type in C can be `signed` (default) or `unsigned`. Unsigned integers cannot be negative but can hold larger positive values:

=== "Python"

    ```python
    # Python integers are always signed and arbitrary precision
    x = 255
    y = -1
    z = 2**64  # No problem — Python handles it
    ```

=== "C"

    ```c
    // Signed: can be negative, smaller positive range
    int x = -1;                // OK

    // Unsigned: non-negative only, larger positive range
    unsigned int y = 4294967295;  // Max value for 32-bit unsigned
    unsigned int z = -1;          // BUG: wraps to 4294967295 (no error!)
    ```

!!! warning "Unsigned Overflow Is Silent"
    In Python, negative numbers just work. In C, assigning a negative value to an unsigned variable silently wraps around. The compiler will not warn you by default. This is a common source of bugs, especially when dealing with packet lengths and offsets in eBPF.

## Kernel-Specific Types: `__u8`, `__u16`, `__u32`, `__u64`

Standard C types like `int` and `long` have platform-dependent sizes. The Linux kernel defines its own types with **guaranteed sizes**. In eBPF programming, you will see these everywhere:

| Kernel Type | Size | Equivalent Standard C | Typical Use in eBPF |
|------------|------|----------------------|---------------------|
| `__u8` | 1 byte | `unsigned char` | Protocol numbers, flags |
| `__u16` | 2 bytes | `unsigned short` | Port numbers, protocol fields |
| `__u32` | 4 bytes | `unsigned int` | IPv4 addresses, PIDs, map keys |
| `__u64` | 8 bytes | `unsigned long long` | Timestamps, combined PID/TGID |
| `__s8` | 1 byte | `signed char` | Signed 8-bit values |
| `__s16` | 2 bytes | `signed short` | Signed 16-bit values |
| `__s32` | 4 bytes | `signed int` | Return codes |
| `__s64` | 8 bytes | `signed long long` | Signed 64-bit values |

You'll also see `u8`, `u16`, `u32`, `u64` (without the underscores) in BCC programs. They are aliases for the same types.

```c
// Typical eBPF code — kernel types everywhere
__u32 src_ip;        // IPv4 address (4 bytes)
__u16 src_port;      // Port number (2 bytes)
__u64 pid_tgid;      // Combined PID and TGID (8 bytes)
__u32 pid = pid_tgid >> 32;  // Extract PID from upper 32 bits
```

!!! tip "Why Kernel Types Matter"
    When you define a BPF map key or value, the kernel needs to know the exact size. `__u32` is always 4 bytes on every architecture. `int` is usually 4 bytes, but the kernel headers use `__u32` to be explicit. Follow the convention — use kernel types in your eBPF programs.

## `sizeof` — Know How Big Things Are

C gives you the `sizeof` operator to check how many bytes a type or variable occupies. There is no Python equivalent because Python objects carry their own size information internally.

=== "Python"

    ```python
    import sys

    x = 42
    print(sys.getsizeof(x))  # 28 bytes! (Python int is an object with overhead)

    # Python integers are objects with reference counts, type pointers, etc.
    # The actual numeric value is a small part of the total memory used
    ```

=== "C"

    ```c
    #include <stdio.h>

    int main() {
        int x = 42;
        printf("int: %lu bytes\n", sizeof(int));       // 4
        printf("char: %lu bytes\n", sizeof(char));      // 1
        printf("long: %lu bytes\n", sizeof(long));      // 8 (on 64-bit)
        printf("__u32: %lu bytes\n", sizeof(__u32));    // 4
        printf("__u64: %lu bytes\n", sizeof(__u64));    // 8
        printf("x: %lu bytes\n", sizeof(x));            // 4
        return 0;
    }
    ```

In Python, a simple integer `42` uses 28 bytes because it's a full object with a reference count, type pointer, and arbitrary-precision storage. In C, the same integer uses exactly 4 bytes — just the number, nothing else.

## Type Casting

Sometimes you need to treat a value as a different type. Python does this with constructor functions. C uses cast syntax.

=== "Python"

    ```python
    x = 65
    c = chr(x)    # Convert int to character: 'A'
    y = float(x)  # Convert int to float: 65.0
    z = int(3.7)  # Convert float to int: 3 (truncates)
    ```

=== "C"

    ```c
    int x = 65;
    char c = (char)x;     // Cast int to char: 'A'
    double y = (double)x; // Cast int to double: 65.0
    int z = (int)3.7;     // Cast double to int: 3 (truncates)
    ```

### Implicit Type Promotion

C automatically promotes smaller types to larger types in expressions. This is called **type promotion** and it can cause subtle bugs:

```c
__u8 a = 200;
__u8 b = 100;
__u8 result = a + b;  // 200 + 100 = 300, but __u8 max is 255
                       // result is 44 (300 - 256), silently wrapped!

// Fix: use a larger type for the result
__u16 safe_result = (__u16)a + (__u16)b;  // 300, correct
```

!!! warning "Type Promotion in eBPF"
    The eBPF verifier tracks value ranges. If you cast a 64-bit value to 32-bit and back, the verifier may lose track of the value's bounds and reject your program. Be deliberate about your casts in eBPF code.

## Variable Declaration and Initialization

=== "Python"

    ```python
    # Variables come into existence when you assign them
    x = 10          # Created and initialized
    print(y)        # NameError: y is not defined
    ```

=== "C"

    ```c
    // Variables must be declared before use
    int x = 10;     // Declared and initialized
    int y;          // Declared but NOT initialized — contains garbage!
    printf("%d\n", y);  // Undefined behavior: could print anything

    // Always initialize your variables
    int z = 0;      // Good practice
    ```

!!! warning "Uninitialized Variables"
    In Python, using an undefined variable is a clear `NameError`. In C, an uninitialized variable contains whatever bytes happened to be in that memory location — it compiles and runs, but produces unpredictable results. The eBPF verifier will reject programs that read uninitialized stack memory, which is actually a safety feature.

## Constants

=== "Python"

    ```python
    # Python convention: UPPERCASE for constants (not enforced)
    MAX_ENTRIES = 1024
    PI = 3.14159
    ```

=== "C"

    ```c
    // Option 1: #define (preprocessor replacement — no type checking)
    #define MAX_ENTRIES 1024
    #define PI 3.14159

    // Option 2: const (type-checked, preferred in general C)
    const int max_entries = 1024;
    const double pi = 3.14159;
    ```

In eBPF programs, `#define` is the standard way to declare constants because it happens at compile time and has zero runtime cost. You'll see it used for map sizes, maximum string lengths, and protocol constants.

```c
#define MAX_MAP_ENTRIES 10240
#define TASK_COMM_LEN 16
#define ETH_P_IP 0x0800
```

## Putting It Together: A Real eBPF Example

Here's how types show up in a real eBPF program that tracks which processes make network connections:

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MAX_ENTRIES 10240

// A struct with kernel types — this will be a BPF map value
struct event_t {
    __u32 pid;          // 4 bytes: process ID
    __u32 uid;          // 4 bytes: user ID
    __u16 port;         // 2 bytes: destination port
    __u16 protocol;     // 2 bytes: protocol number
    __u32 dst_addr;     // 4 bytes: destination IPv4 address
};

SEC("kprobe/__x64_sys_connect")
int trace_connect(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;        // Upper 32 bits = PID
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;  // Lower 32 bits = UID

    // ... parse connection details and store in map ...
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

Every variable has an explicit type. Every type has a known, fixed size. There is no ambiguity about how much memory anything uses.

## Exercises

1. **Size explorer**: Write a C program that prints the `sizeof` every basic type: `char`, `short`, `int`, `long`, `long long`, `float`, `double`, `__u8`, `__u16`, `__u32`, `__u64`. Predict the values before running.

2. **Overflow detector**: Declare a `__u8` variable and assign it the value `256`. What value does it actually hold? Try the same with `__u16` and `65536`. Explain why.

3. **PID extraction**: The BPF helper `bpf_get_current_pid_tgid()` returns a `__u64` where the upper 32 bits are the PID and the lower 32 bits are the TGID. Write C code that extracts both values into separate `__u32` variables. Then write the Python equivalent using bit operations.

4. **Type casting chain**: Start with the integer `65`. Cast it to `char` (what character is it?), then cast that to `__u16`, then shift it left by 8. What is the final value? Work it out on paper first, then verify in C.

5. **Python comparison**: Write a Python script using `ctypes` that demonstrates the difference between `ctypes.c_uint8`, `ctypes.c_uint16`, `ctypes.c_uint32`, and `ctypes.c_uint64`. Assign a value larger than each type can hold and observe the truncation.
