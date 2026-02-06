# Chapter 3: Structs & Unions

Network packets, kernel data structures, BPF map values — in eBPF programming, you spend most of your time working with **structs**. A struct in C is like a Python class with only attributes (no methods) — it groups related data together under a single name.

If you have ever used Python's `dataclasses` or `namedtuple`, structs will feel familiar. The difference is that C structs have a fixed memory layout that you control precisely, byte by byte.

## Python Classes vs C Structs

=== "Python"

    ```python
    from dataclasses import dataclass

    @dataclass
    class Connection:
        pid: int          # Process ID
        src_ip: int       # Source IP (as integer)
        dst_ip: int       # Destination IP
        src_port: int     # Source port
        dst_port: int     # Destination port

    conn = Connection(
        pid=1234,
        src_ip=0x0A000001,      # 10.0.0.1
        dst_ip=0xC0A80001,      # 192.168.0.1
        src_port=54321,
        dst_port=80
    )

    print(conn.pid)         # 1234
    print(conn.dst_port)    # 80
    ```

=== "C"

    ```c
    struct connection {
        __u32 pid;          // 4 bytes: Process ID
        __u32 src_ip;       // 4 bytes: Source IP
        __u32 dst_ip;       // 4 bytes: Destination IP
        __u16 src_port;     // 2 bytes: Source port
        __u16 dst_port;     // 2 bytes: Destination port
    };

    struct connection conn = {
        .pid = 1234,
        .src_ip = 0x0A000001,   // 10.0.0.1
        .dst_ip = 0xC0A80001,   // 192.168.0.1
        .src_port = 54321,
        .dst_port = 80
    };

    printf("%u\n", conn.pid);       // 1234
    printf("%u\n", conn.dst_port);  // 80
    ```

!!! note "Designated Initializers"
    The `.field = value` syntax in C is called a **designated initializer**. It lets you initialize fields by name instead of position, just like Python keyword arguments. This is the preferred style in kernel code because it's more readable and less error-prone when structs have many fields.

## Struct Declaration and Definition

In C, you declare a struct with the `struct` keyword, followed by the struct name and its fields in curly braces:

```c
// Declaration: defines the struct type
struct packet_info {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
};

// Usage: declare a variable of that type
struct packet_info pkt;
pkt.src_ip = 0x0A000001;
pkt.protocol = 6;  // TCP
```

Every time you use the struct, you must include the `struct` keyword — `struct packet_info`, not just `packet_info`. This is different from Python, where the class name alone is sufficient.

### typedef: Creating Type Aliases

To avoid typing `struct` everywhere, use `typedef`:

```c
// Define the struct and create an alias
typedef struct {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
} packet_info_t;

// Now you can use the alias directly
packet_info_t pkt;
pkt.src_ip = 0x0A000001;
```

!!! tip "Kernel Convention"
    Linux kernel code typically uses `struct name` (without typedef), while userspace code often uses `typedef`. In eBPF programs, you will see both styles. Follow the convention of the codebase you are working in. BPF maps often use typedef'd types like `__u32` for keys and values.

## Memory Layout: What's Actually in Memory

This is the critical difference between Python and C. In Python, a dataclass is an object with pointers to each attribute. In C, a struct is a contiguous block of memory where each field occupies a specific offset.

```c
struct connection {
    __u32 pid;          // Offset 0, 4 bytes
    __u32 src_ip;       // Offset 4, 4 bytes
    __u32 dst_ip;       // Offset 8, 4 bytes
    __u16 src_port;     // Offset 12, 2 bytes
    __u16 dst_port;     // Offset 14, 2 bytes
};
// Total size: 16 bytes, all contiguous

// Memory layout (each box = 1 byte):
// +----+----+----+----+----+----+----+----+
// |       pid       |      src_ip       |
// +----+----+----+----+----+----+----+----+
// |      dst_ip       | src_port| dst_port|
// +----+----+----+----+----+----+----+----+
```

Use `sizeof` and `offsetof` to inspect the layout:

```c
#include <stddef.h>

printf("Size of struct: %lu\n", sizeof(struct connection));  // 16
printf("Offset of pid: %lu\n", offsetof(struct connection, pid));       // 0
printf("Offset of src_ip: %lu\n", offsetof(struct connection, src_ip)); // 4
printf("Offset of dst_ip: %lu\n", offsetof(struct connection, dst_ip)); // 8
printf("Offset of src_port: %lu\n", offsetof(struct connection, src_port)); // 12
printf("Offset of dst_port: %lu\n", offsetof(struct connection, dst_port)); // 14
```

## Padding and Alignment

The compiler sometimes inserts invisible **padding bytes** between fields to align them to memory boundaries. This can change your struct's size in unexpected ways.

```c
// Watch what happens with mixed sizes
struct misaligned {
    __u8  a;    // 1 byte
    __u32 b;    // 4 bytes
    __u8  c;    // 1 byte
};

// You might expect: 1 + 4 + 1 = 6 bytes
// Actual size: 12 bytes!

// Memory layout:
// +----+----+----+----+----+----+----+----+
// | a  | pad| pad| pad|        b          |
// +----+----+----+----+----+----+----+----+
// | c  | pad| pad| pad|
// +----+----+----+----+
```

Why? On most architectures, a 4-byte value like `__u32` must be aligned to a 4-byte boundary (its address must be divisible by 4). The compiler inserts 3 padding bytes after `a` to align `b`, and 3 more after `c` to align the struct's total size for arrays.

### Avoiding Padding: Reorder Fields

```c
// Better layout: group by size, largest first
struct aligned {
    __u32 b;    // 4 bytes, offset 0
    __u8  a;    // 1 byte, offset 4
    __u8  c;    // 1 byte, offset 5
};
// Size: 8 bytes (6 bytes of data + 2 bytes padding at the end)

// Even better: pack small fields together
struct compact {
    __u32 b;    // 4 bytes, offset 0
    __u8  a;    // 1 byte, offset 4
    __u8  c;    // 1 byte, offset 5
    __u16 pad;  // Explicit padding to 8-byte alignment (optional)
};
```

!!! warning "Padding in BPF Maps"
    When you define a struct as a BPF map key or value, the kernel uses the struct's bytes for hashing and comparison. Padding bytes contain **garbage** — they are not initialized. Two structs that look identical in your code might hash differently because their padding bytes differ. Always initialize your structs with `= {}` or use `__attribute__((packed))` to eliminate padding.

### Packed Structs: Eliminating Padding

Use `__attribute__((packed))` to remove all padding:

```c
struct __attribute__((packed)) packet_header {
    __u8  version;    // 1 byte
    __u32 src_ip;     // 4 bytes, immediately after version
    __u32 dst_ip;     // 4 bytes
    __u16 length;     // 2 bytes
};
// Size: exactly 11 bytes (no padding)
```

!!! warning "Packed Struct Tradeoffs"
    Packed structs can cause performance issues on some architectures because unaligned memory access is slower. They can also cause problems with certain BPF helpers. Use packing when you need to match an exact wire format (like parsing network headers), but prefer natural alignment for BPF map values.

## Accessing Struct Members

There are two ways to access struct members, depending on whether you have a struct value or a pointer:

```c
struct connection conn;
struct connection *ptr = &conn;

// Direct access: use dot (.)
conn.pid = 1234;
conn.src_port = 8080;

// Pointer access: use arrow (->)
ptr->pid = 1234;
ptr->src_port = 8080;

// ptr->field is shorthand for (*ptr).field
```

In eBPF, you almost always work with **pointers** to structs because:

1. You're pointing into packet data (which is a memory buffer)
2. You're reading BPF map values (which return pointers)
3. Context structs like `struct xdp_md *ctx` are always pointers

```c
// Typical eBPF pattern: working with pointers
SEC("xdp")
int parse_packet(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;      // ctx is a pointer, use ->
    struct ethhdr *eth = data;                  // eth is a pointer
    __u16 proto = eth->h_proto;                 // access via ->

    return XDP_PASS;
}
```

## Nested Structs

Structs can contain other structs:

=== "Python"

    ```python
    @dataclass
    class Endpoint:
        ip: int
        port: int

    @dataclass
    class Connection:
        src: Endpoint
        dst: Endpoint
        pid: int

    conn = Connection(
        src=Endpoint(ip=0x0A000001, port=54321),
        dst=Endpoint(ip=0xC0A80001, port=80),
        pid=1234
    )
    print(conn.src.port)  # 54321
    ```

=== "C"

    ```c
    struct endpoint {
        __u32 ip;
        __u16 port;
    };

    struct connection {
        struct endpoint src;
        struct endpoint dst;
        __u32 pid;
    };

    struct connection conn = {
        .src = { .ip = 0x0A000001, .port = 54321 },
        .dst = { .ip = 0xC0A80001, .port = 80 },
        .pid = 1234
    };

    printf("%u\n", conn.src.port);  // 54321
    ```

The nested structs are embedded **inline** — `conn.src` is not a pointer, it's the actual `struct endpoint` data within `conn`.

## Unions: Same Memory, Different Interpretations

A **union** looks like a struct but with a key difference: all fields share the same memory. The size of a union is the size of its largest member. Only one field is "active" at a time.

=== "Python"

    ```python
    # Python doesn't have unions, but you can simulate with a class
    class IPAddress:
        def __init__(self, as_int: int):
            self._value = as_int

        @property
        def as_int(self) -> int:
            return self._value

        @property
        def as_bytes(self) -> bytes:
            return self._value.to_bytes(4, 'big')

    ip = IPAddress(0x0A000001)
    print(hex(ip.as_int))   # 0xa000001
    print(ip.as_bytes)      # b'\n\x00\x00\x01' (10.0.0.1)
    ```

=== "C"

    ```c
    union ip_address {
        __u32 as_int;           // View as single 32-bit integer
        __u8  as_bytes[4];      // View as 4 individual bytes
    };

    union ip_address ip;
    ip.as_int = 0x0A000001;

    printf("0x%x\n", ip.as_int);         // 0xa000001
    printf("%d.%d.%d.%d\n",
        ip.as_bytes[0], ip.as_bytes[1],
        ip.as_bytes[2], ip.as_bytes[3]);  // 10.0.0.1 (or reversed, see byte order chapter)
    ```

### Unions in Kernel Structures

You will encounter unions frequently in kernel networking structures. For example, socket addresses:

```c
// Simplified version of sockaddr_storage
union sockaddr_any {
    struct sockaddr_in  v4;   // IPv4
    struct sockaddr_in6 v6;   // IPv6
};

// The union is large enough for either type
// You check a flag to know which interpretation to use
```

## Structs as BPF Map Keys and Values

This is where understanding structs becomes essential for eBPF. When you define a BPF map, you specify the key and value types. Structs let you create composite keys and rich value types:

```c
// A map key that identifies a connection by its 4-tuple
struct conn_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

// A map value that stores connection statistics
struct conn_stats {
    __u64 packets;
    __u64 bytes;
    __u64 start_time;
    __u64 last_seen;
};

// Define a hash map with struct key and struct value
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct conn_key);
    __type(value, struct conn_stats);
} connections SEC(".maps");

// Using the map
SEC("xdp")
int count_packets(struct xdp_md *ctx) {
    struct conn_key key = {};
    // ... populate key from packet ...

    struct conn_stats *stats = bpf_map_lookup_elem(&connections, &key);
    if (stats) {
        stats->packets++;
    }
    return XDP_PASS;
}
```

!!! warning "Initialize Your Structs"
    Always initialize structs with `= {}` or `= {0}` before using them as map keys. Uninitialized padding bytes will cause map lookups to fail because the key bytes won't match.

## Anonymous Structs and Unions

C11 allows anonymous (unnamed) structs and unions inside other structs:

```c
struct event {
    __u32 type;
    union {
        struct {
            __u32 pid;
            __u32 tid;
        };  // anonymous struct
        struct {
            __u32 src_ip;
            __u16 src_port;
        };  // anonymous struct
    };      // anonymous union
};

struct event e;
e.type = 1;
e.pid = 1234;   // Access without naming the intermediate struct
e.tid = 5678;
```

This pattern is common in kernel event structures where different event types carry different data.

## Kernel Network Structs You'll Use Constantly

Here are the structs you will work with in almost every eBPF networking program:

| Struct | Header | Purpose |
|--------|--------|---------|
| `struct ethhdr` | `<linux/if_ether.h>` | Ethernet header (MACs, protocol) |
| `struct iphdr` | `<linux/ip.h>` | IPv4 header |
| `struct ipv6hdr` | `<linux/ipv6.h>` | IPv6 header |
| `struct tcphdr` | `<linux/tcp.h>` | TCP header |
| `struct udphdr` | `<linux/udp.h>` | UDP header |
| `struct sockaddr_in` | `<netinet/in.h>` | IPv4 socket address |
| `struct sockaddr_in6` | `<netinet/in6.h>` | IPv6 socket address |

We cover these in detail in [Chapter 8: Networking Structs](ch08-networking-structs.md).

## Exercises

1. **Size calculator**: Define a struct with fields `__u8`, `__u32`, `__u16`, `__u64` in that order. Print its size with `sizeof`. Then reorder the fields largest-to-smallest and print again. Explain the difference.

2. **Offset explorer**: Create a struct with 5 fields of varying sizes. Use `offsetof()` to print the offset of each field. Draw the memory layout by hand, marking where padding bytes are inserted.

3. **Packed comparison**: Take the struct from exercise 1 and add `__attribute__((packed))`. Print the new size and offsets. When would you use this in eBPF?

4. **BPF map key**: Design a struct to use as a BPF map key for tracking connections by 5-tuple (src IP, dst IP, src port, dst port, protocol). Consider: what types should you use? How do you ensure consistent padding?

5. **Union practice**: Create a union that lets you view a 32-bit IPv4 address as either a `__u32` or an array of 4 `__u8` bytes. Write code that sets the address via the integer view and prints it via the byte array view.

6. **Python comparison**: Write a Python `struct` module equivalent of your C struct from exercise 4. Use `struct.pack()` to create the binary representation and compare its size to your C struct.
