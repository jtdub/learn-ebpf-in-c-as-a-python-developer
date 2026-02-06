# Chapter 7: Preprocessor & Macros

Before your C code is compiled, it goes through a **preprocessor** that performs text transformations. This is where `#include`, `#define`, and `#ifdef` live. Python has nothing equivalent — these directives modify your source code before the compiler sees it.

In eBPF programming, you encounter the preprocessor constantly. Every eBPF program starts with `#include` directives to bring in kernel headers. The `SEC()` macro that marks program entry points is a preprocessor construct. BPF map definitions use macros. Understanding the preprocessor is essential.

## How the Preprocessor Works

The preprocessor runs before compilation, transforming your source code:

```
Source code (.c)  →  Preprocessor  →  Expanded code  →  Compiler  →  Object file
```

You can see the preprocessor output with `gcc -E`:

```bash
gcc -E my_program.c -o my_program.i
# The .i file contains the preprocessed (expanded) source
```

All preprocessor directives start with `#` and are not C statements — they don't end with semicolons.

## #include: Importing Definitions

Python uses `import` to bring in modules. C uses `#include` to **copy the contents of a header file** directly into your source:

=== "Python"

    ```python
    import os
    import socket
    from typing import Dict, List

    # Python loads modules at runtime
    # Modules are objects with attributes
    ```

=== "C"

    ```c
    #include <stdio.h>        // Standard I/O (printf, etc.)
    #include <linux/bpf.h>    // BPF definitions
    #include <bpf/bpf_helpers.h>  // BPF helper functions

    // The preprocessor literally copies file contents here
    // No runtime module system — it's compile-time text insertion
    ```

### Angle Brackets vs Quotes

```c
#include <stdio.h>      // Search system include directories
#include "my_header.h"  // Search current directory first, then system
```

Use `<>` for system headers and `""` for your own project headers.

### What's in a Header File?

Header files (`.h`) contain **declarations**, not implementations:

- Function prototypes (`int foo(int x);`)
- Struct definitions
- Macro definitions
- Type aliases (`typedef`)
- Constants

```c
// my_types.h
#ifndef MY_TYPES_H
#define MY_TYPES_H

struct event {
    __u32 pid;
    char comm[16];
};

#define MAX_ENTRIES 1024

#endif
```

### Common eBPF Headers

| Header | What It Provides |
|--------|-----------------|
| `<linux/bpf.h>` | BPF map types, program types, helper definitions |
| `<bpf/bpf_helpers.h>` | BPF helper function declarations (libbpf) |
| `<bpf/bpf_endian.h>` | Byte order conversion macros |
| `<linux/if_ether.h>` | Ethernet header struct, protocol constants |
| `<linux/ip.h>` | IPv4 header struct |
| `<linux/tcp.h>` | TCP header struct |
| `<linux/udp.h>` | UDP header struct |

## #define: Creating Macros

`#define` creates text substitutions. The preprocessor replaces every occurrence of the macro name with its definition:

### Simple Constants

```c
#define MAX_ENTRIES 1024
#define PI 3.14159
#define DEBUG 1

// Usage:
int arr[MAX_ENTRIES];  // Becomes: int arr[1024];
```

This is like Python's constants, but the replacement happens at compile time:

=== "Python"

    ```python
    MAX_ENTRIES = 1024
    arr = [0] * MAX_ENTRIES  # MAX_ENTRIES is a variable
    ```

=== "C"

    ```c
    #define MAX_ENTRIES 1024
    int arr[MAX_ENTRIES];    // MAX_ENTRIES is replaced by 1024
    ```

### Function-like Macros

Macros can take parameters:

```c
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define SQUARE(x) ((x) * (x))

int smallest = MIN(10, 20);   // Becomes: ((10) < (20) ? (10) : (20))
int sq = SQUARE(5);           // Becomes: ((5) * (5))
```

!!! warning "Macro Pitfalls"
    Macros are text substitution, not functions. This causes problems:

    ```c
    #define SQUARE(x) x * x

    int a = SQUARE(3 + 2);    // Becomes: 3 + 2 * 3 + 2 = 11, not 25!
    // Fix: #define SQUARE(x) ((x) * (x))

    #define DOUBLE(x) ((x) + (x))
    int b = DOUBLE(i++);      // Becomes: ((i++) + (i++)) — increments twice!
    ```

    **Always wrap parameters and the entire expression in parentheses.**

### Multi-line Macros

Use `\` to continue a macro on the next line:

```c
#define PRINT_DEBUG(fmt, ...) \
    do { \
        if (DEBUG) \
            printf("[DEBUG] " fmt "\n", ##__VA_ARGS__); \
    } while (0)

// Usage:
PRINT_DEBUG("value = %d", x);
```

The `do { ... } while (0)` pattern ensures the macro behaves like a single statement.

## Conditional Compilation: #ifdef, #ifndef, #if

The preprocessor can include or exclude code based on conditions:

### #ifdef / #ifndef — Is a Macro Defined?

```c
#define DEBUG 1

#ifdef DEBUG
    printf("Debug mode enabled\n");
#endif

#ifndef PRODUCTION
    // This code is included only if PRODUCTION is NOT defined
    enable_all_logging();
#endif
```

### Include Guards

Header files use `#ifndef` to prevent double inclusion:

```c
// my_header.h
#ifndef MY_HEADER_H
#define MY_HEADER_H

// Header contents here

#endif // MY_HEADER_H
```

Without this, including the same header twice causes duplicate definition errors.

Modern alternative: `#pragma once` (non-standard but widely supported):

```c
#pragma once

// Header contents
```

### #if — Numeric Conditions

```c
#define VERSION 2

#if VERSION == 1
    // Code for version 1
#elif VERSION == 2
    // Code for version 2
#else
    // Default code
#endif

#if DEBUG && (VERSION > 1)
    // Debug code for version 2+
#endif
```

### Platform-Specific Code

```c
#ifdef __linux__
    // Linux-specific code
#elif defined(__APPLE__)
    // macOS-specific code
#elif defined(_WIN32)
    // Windows-specific code
#endif
```

## Special Macros

The preprocessor provides built-in macros:

| Macro | Value | Example |
|-------|-------|---------|
| `__FILE__` | Current filename | `"my_program.c"` |
| `__LINE__` | Current line number | `42` |
| `__func__` | Current function name | `"main"` |
| `__DATE__` | Compilation date | `"Feb 6 2026"` |
| `__TIME__` | Compilation time | `"14:30:22"` |

```c
#define LOG(msg) printf("[%s:%d] %s\n", __FILE__, __LINE__, msg)

LOG("something happened");
// Prints: [my_program.c:42] something happened
```

## eBPF-Specific Macros

### SEC() — Section Annotation

The `SEC()` macro places code or data in a specific ELF section, which tells the loader what type of eBPF program it is:

```c
// Definition (from bpf_helpers.h):
#define SEC(NAME) __attribute__((section(NAME), used))

// Usage:
SEC("xdp")
int my_xdp_program(struct xdp_md *ctx) {
    return XDP_PASS;
}

SEC("kprobe/__x64_sys_execve")
int trace_execve(struct pt_regs *ctx) {
    return 0;
}
```

Common section names:

| Section | Program Type |
|---------|-------------|
| `"xdp"` | XDP (eXpress Data Path) |
| `"tc"` | Traffic Control |
| `"kprobe/function"` | Kprobe at function entry |
| `"kretprobe/function"` | Kprobe at function return |
| `"tracepoint/category/name"` | Tracepoint |
| `"cgroup/connect4"` | Cgroup IPv4 connect |

### BPF Map Definitions

Modern eBPF uses a macro-based syntax for map definitions:

```c
// BTF-style map definition (modern, libbpf)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} my_map SEC(".maps");

// The __uint and __type macros are defined in bpf_helpers.h:
// #define __uint(name, val) int (*name)[val]
// #define __type(name, val) typeof(val) *name
```

### BCC-Style Map Definitions

BCC uses different macros:

```c
// BCC map definition
BPF_HASH(my_map, u32, u64);
BPF_ARRAY(my_array, struct event, 1024);
BPF_PERF_OUTPUT(events);
```

## Stringification and Token Pasting

Advanced macro features you'll occasionally encounter:

### Stringification (#)

The `#` operator turns a macro argument into a string:

```c
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

printf("%s\n", STRINGIFY(hello));  // Prints: hello
printf("%s\n", TOSTRING(123));     // Prints: 123
```

### Token Pasting (##)

The `##` operator concatenates tokens:

```c
#define CONCAT(a, b) a##b

int CONCAT(my, var) = 42;  // Creates variable: myvar
CONCAT(my, func)();        // Calls function: myfunc()
```

Used in eBPF for generating unique names:

```c
#define BPF_MAP(name, ...) \
    struct { \
        __VA_ARGS__ \
    } name SEC(".maps")
```

## Preprocessor vs const

When should you use `#define` vs `const`?

```c
// Preprocessor constant
#define MAX_SIZE 1024
int arr[MAX_SIZE];  // Works — MAX_SIZE is known at compile time

// const variable
const int max_size = 1024;
// int arr[max_size];  // Might not work — depends on compiler/standard
```

For eBPF and array sizes, prefer `#define`. The preprocessor value is guaranteed to be a compile-time constant.

!!! tip "enum for Related Constants"
    For related constants, use `enum` instead of multiple `#define`:

    ```c
    // Instead of:
    #define TCP 6
    #define UDP 17
    #define ICMP 1

    // Use:
    enum protocol {
        PROTO_ICMP = 1,
        PROTO_TCP = 6,
        PROTO_UDP = 17
    };
    ```
    Enums have type checking and show up in debuggers.

## Exercises

1. **Include guard**: Create a header file with a struct definition and proper include guards. Include it twice from a `.c` file and verify it compiles without errors.

2. **Debug macro**: Create a `DEBUG_LOG(level, msg)` macro that only prints when `DEBUG_LEVEL >= level`. Use conditional compilation.

3. **Type-safe min/max**: The `MIN`/`MAX` macros have problems with side effects. Research and implement a type-safe version using GCC's `typeof` extension:
    ```c
    #define MIN(a, b) ({ typeof(a) _a = (a); typeof(b) _b = (b); _a < _b ? _a : _b; })
    ```

4. **BPF section explorer**: Write a simple program with multiple `SEC()` annotations for different program types. Use `llvm-objdump -h` to see the ELF sections created.

5. **Preprocessor output**: Take an eBPF program that uses `#include` and `SEC()` macros. Run it through `clang -E` to see the preprocessed output. How many lines does the preprocessor add?

6. **Platform detection**: Write a macro that defines `PLATFORM_NAME` as a string based on the current platform (`"Linux"`, `"macOS"`, `"Windows"`, or `"Unknown"`).

7. **Stringification use case**: Create a macro that takes a variable name and prints both the name and the value:
    ```c
    int my_value = 42;
    PRINT_VAR(my_value);  // Should print: my_value = 42
    ```
