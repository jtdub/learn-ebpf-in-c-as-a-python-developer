# Python to C Reference

Quick reference for translating Python concepts to C, specifically for eBPF development.

## Variables and Types

=== "Python"
    ```python
    # Dynamic typing
    x = 42
    name = "hello"
    pi = 3.14
    flag = True
    ```

=== "C"
    ```c
    // Static typing required
    int x = 42;
    char name[] = "hello";  // or char *name = "hello";
    double pi = 3.14;
    bool flag = true;       // #include <stdbool.h>
    ```

### Integer Types

| Python | C | eBPF Type | Size |
|--------|---|-----------|------|
| `int` | `int` | `__s32` | 4 bytes |
| `int` | `unsigned int` | `__u32` | 4 bytes |
| `int` | `long long` | `__s64` | 8 bytes |
| `int` | `unsigned long long` | `__u64` | 8 bytes |
| `int` | `short` | `__s16` | 2 bytes |
| `int` | `unsigned char` | `__u8` | 1 byte |

## Strings

=== "Python"
    ```python
    # Strings are objects
    s = "hello"
    length = len(s)
    combined = s + " world"
    contains = "ell" in s
    ```

=== "C"
    ```c
    // Strings are char arrays ending in \0
    char s[] = "hello";
    int length = strlen(s);

    // Concatenation requires buffer
    char combined[32];
    strcpy(combined, s);
    strcat(combined, " world");

    // Contains check
    int contains = strstr(s, "ell") != NULL;
    ```

### String Operations in eBPF

```c
// Reading strings safely
char buf[64];
bpf_probe_read_user_str(buf, sizeof(buf), user_str_ptr);

// Comparing strings (first n chars)
if (__builtin_memcmp(str1, str2, 5) == 0) {
    // Match
}

// No strcat/strcpy in eBPF - use manual copy
#pragma unroll
for (int i = 0; i < 16 && src[i]; i++) {
    dst[i] = src[i];
}
```

## Data Structures

### Lists/Arrays

=== "Python"
    ```python
    # Dynamic list
    numbers = [1, 2, 3, 4, 5]
    numbers.append(6)
    first = numbers[0]
    length = len(numbers)
    ```

=== "C"
    ```c
    // Fixed-size array
    int numbers[5] = {1, 2, 3, 4, 5};
    // Cannot append - size is fixed
    int first = numbers[0];
    int length = sizeof(numbers) / sizeof(numbers[0]);
    ```

### Dictionaries/Maps

=== "Python"
    ```python
    # Dict with any types
    data = {}
    data["key"] = 42
    value = data.get("key")
    if "key" in data:
        del data["key"]
    ```

=== "C (eBPF)"
    ```c
    // BPF hash map
    struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __type(key, __u32);
        __type(value, __u64);
        __uint(max_entries, 1024);
    } data SEC(".maps");

    // Insert
    __u32 key = 1;
    __u64 val = 42;
    bpf_map_update_elem(&data, &key, &val, BPF_ANY);

    // Lookup
    __u64 *valp = bpf_map_lookup_elem(&data, &key);
    if (valp) {
        // Use *valp
    }

    // Delete
    bpf_map_delete_elem(&data, &key);
    ```

### Classes/Structs

=== "Python"
    ```python
    class Event:
        def __init__(self, pid, comm):
            self.pid = pid
            self.comm = comm

        def display(self):
            print(f"{self.pid}: {self.comm}")

    e = Event(1234, "bash")
    e.display()
    ```

=== "C"
    ```c
    // Struct definition
    struct event {
        __u32 pid;
        char comm[16];
    };

    // No methods - use functions
    void display(struct event *e) {
        // bpf_printk or userspace printf
    }

    // Usage
    struct event e = {
        .pid = 1234,
        .comm = "bash"
    };
    display(&e);
    ```

## Control Flow

### Conditionals

=== "Python"
    ```python
    if x > 10:
        result = "big"
    elif x > 5:
        result = "medium"
    else:
        result = "small"
    ```

=== "C"
    ```c
    char *result;
    if (x > 10) {
        result = "big";
    } else if (x > 5) {
        result = "medium";
    } else {
        result = "small";
    }
    ```

### Loops

=== "Python"
    ```python
    # For loop
    for i in range(10):
        process(i)

    # While loop
    while condition:
        do_something()

    # For each
    for item in items:
        handle(item)
    ```

=== "C"
    ```c
    // For loop
    for (int i = 0; i < 10; i++) {
        process(i);
    }

    // While loop
    while (condition) {
        do_something();
    }

    // No for-each - use index
    for (int i = 0; i < array_len; i++) {
        handle(items[i]);
    }
    ```

### Loops in eBPF

```c
// Bounded loop (verifier requires known bounds)
#pragma unroll
for (int i = 0; i < 16; i++) {
    // Process
}

// Variable bound (needs bpf_loop helper, kernel 5.17+)
// Or use manual unrolling
```

## Functions

=== "Python"
    ```python
    def process_data(data, count=10):
        """Process data with optional count."""
        result = []
        for item in data[:count]:
            result.append(transform(item))
        return result
    ```

=== "C"
    ```c
    // No default arguments, no docstrings
    // Return type must be specified

    int* process_data(int *data, int count) {
        static int result[100];  // Must manage memory
        for (int i = 0; i < count && i < 100; i++) {
            result[i] = transform(data[i]);
        }
        return result;
    }

    // Or with pointer parameter for output
    void process_data(int *data, int count, int *result) {
        for (int i = 0; i < count; i++) {
            result[i] = transform(data[i]);
        }
    }
    ```

### eBPF Functions

```c
// Static inline for BPF (always inlined)
static __always_inline int helper_func(int x) {
    return x * 2;
}

// BPF subprograms (limited support)
__noinline int subprog(int x) {
    return x + 1;
}
```

## Memory Management

=== "Python"
    ```python
    # Automatic memory management
    data = [1, 2, 3]  # Allocated automatically
    data = None       # Garbage collected
    ```

=== "C"
    ```c
    // Manual memory management (userspace)
    int *data = malloc(3 * sizeof(int));
    data[0] = 1; data[1] = 2; data[2] = 3;
    free(data);  // Must free manually

    // In eBPF: No malloc/free
    // Use stack (limited to 512 bytes)
    int data[3] = {1, 2, 3};

    // Or use maps for larger data
    ```

## Pointers

=== "Python"
    ```python
    # No explicit pointers
    # Everything is a reference
    x = [1, 2, 3]
    y = x  # y references same list
    y[0] = 99  # x[0] is now 99
    ```

=== "C"
    ```c
    // Explicit pointers
    int arr[3] = {1, 2, 3};
    int *ptr = arr;       // Pointer to first element

    *ptr = 99;            // Modify through pointer
    ptr++;                // Move to next element
    int val = *ptr;       // Dereference (val = 2)

    // Pointer to struct
    struct event e;
    struct event *ep = &e;
    ep->pid = 1234;       // Arrow for pointer member access
    ```

## Error Handling

=== "Python"
    ```python
    try:
        result = risky_operation()
    except ValueError as e:
        print(f"Error: {e}")
    except Exception:
        print("Unknown error")
    finally:
        cleanup()
    ```

=== "C"
    ```c
    // No exceptions - use return codes
    int result = risky_operation();
    if (result < 0) {
        if (result == -EINVAL) {
            printf("Invalid argument\n");
        } else {
            printf("Error: %d\n", result);
        }
    }
    cleanup();  // Manual cleanup

    // In eBPF
    void *val = bpf_map_lookup_elem(&map, &key);
    if (!val) {
        return 0;  // Early return on error
    }
    ```

## Bitwise Operations

=== "Python"
    ```python
    x = 0b1010
    y = 0b1100

    and_result = x & y    # 0b1000
    or_result = x | y     # 0b1110
    xor_result = x ^ y    # 0b0110
    not_result = ~x       # Inverted
    left = x << 2         # 0b101000
    right = x >> 1        # 0b0101
    ```

=== "C"
    ```c
    int x = 0b1010;  // or 0xA
    int y = 0b1100;  // or 0xC

    int and_result = x & y;    // 0b1000
    int or_result = x | y;     // 0b1110
    int xor_result = x ^ y;    // 0b0110
    int not_result = ~x;       // Inverted
    int left = x << 2;         // 0b101000
    int right = x >> 1;        // 0b0101
    ```

## Network Byte Order

=== "Python"
    ```python
    import struct
    import socket

    # Pack integer as network byte order
    packed = struct.pack('!I', 12345)

    # Convert IP string to integer
    ip_int = struct.unpack('!I', socket.inet_aton('192.168.1.1'))[0]

    # Use socket functions
    port_net = socket.htons(80)
    port_host = socket.ntohs(port_net)
    ```

=== "C"
    ```c
    #include <arpa/inet.h>

    // Host to network
    uint16_t port_net = htons(80);
    uint32_t ip_net = htonl(0xC0A80101);  // 192.168.1.1

    // Network to host
    uint16_t port_host = ntohs(port_net);
    uint32_t ip_host = ntohl(ip_net);

    // In eBPF use bpf_ prefix
    __be16 port_be = bpf_htons(80);
    __u16 port = bpf_ntohs(port_be);
    ```

## Common Patterns

### Null/None Checks

=== "Python"
    ```python
    if data is None:
        return

    if data:  # Truthy check
        process(data)
    ```

=== "C"
    ```c
    if (data == NULL) {
        return;
    }

    // No truthy - explicit checks
    if (data != NULL && data->count > 0) {
        process(data);
    }
    ```

### String Formatting

=== "Python"
    ```python
    msg = f"PID {pid}: {comm}"
    msg = "PID {}: {}".format(pid, comm)
    msg = "PID %d: %s" % (pid, comm)
    ```

=== "C"
    ```c
    // Using sprintf (userspace)
    char msg[64];
    snprintf(msg, sizeof(msg), "PID %d: %s", pid, comm);

    // In eBPF - use bpf_printk for debug only
    bpf_printk("PID %d: %s", pid, comm);
    ```

### Context Managers / RAII

=== "Python"
    ```python
    with open('file.txt') as f:
        data = f.read()
    # File automatically closed
    ```

=== "C"
    ```c
    // No context managers - manual cleanup
    FILE *f = fopen("file.txt", "r");
    if (f == NULL) {
        return -1;
    }

    // Read data...

    fclose(f);  // Must close manually

    // Use goto for cleanup in complex cases
    int func() {
        int ret = -1;
        FILE *f = fopen("file.txt", "r");
        if (!f) goto out;

        // Work...
        ret = 0;

    out:
        if (f) fclose(f);
        return ret;
    }
    ```

## Type Casting

=== "Python"
    ```python
    x = int("42")
    y = float(42)
    s = str(42)
    b = bool(1)
    ```

=== "C"
    ```c
    // Explicit casts
    int x = atoi("42");      // String to int (userspace)
    float y = (float)42;
    // No easy int-to-string in C

    // Type casting
    void *ptr = some_pointer;
    struct event *e = (struct event *)ptr;

    // In eBPF
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = (struct ethhdr *)data;
    ```

## Quick Reference Table

| Python | C | eBPF Notes |
|--------|---|------------|
| `len(x)` | `sizeof(x)/sizeof(x[0])` | Compile-time only |
| `x.append(y)` | N/A | Use fixed-size arrays or maps |
| `dict[key]` | `bpf_map_lookup_elem()` | Returns pointer, check NULL |
| `dict[key] = val` | `bpf_map_update_elem()` | Pass pointers |
| `del dict[key]` | `bpf_map_delete_elem()` | |
| `print()` | `bpf_printk()` | Debug only, limited format |
| `time.time()` | `bpf_ktime_get_ns()` | Nanoseconds since boot |
| `os.getpid()` | `bpf_get_current_pid_tgid()` | Returns pid<<32\|tid |
| `pass` | `;` or `{}` | Empty statement |
| `lambda x: x*2` | N/A | Use regular functions |
| `*args, **kwargs` | N/A | Fixed parameters only |
