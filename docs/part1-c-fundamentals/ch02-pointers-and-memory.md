# Chapter 2: Pointers & Memory

This is the chapter that separates Python developers from C programmers. Pointers are the single most important concept to master for eBPF development. Every packet you parse, every struct you access, every BPF helper you call involves pointers. There is no avoiding them.

The good news: the concept is simpler than its reputation. A pointer is just a variable that holds a memory address. That's it. The syntax is what makes it feel complicated.

## Python References vs C Pointers

In Python, every variable is a reference — a name that points to an object somewhere in memory. You just never see the addresses.

=== "Python"

    ```python
    x = [1, 2, 3]
    y = x          # y points to the SAME list object
    y.append(4)
    print(x)       # [1, 2, 3, 4] — both names see the change

    # id() gives the memory address of the object
    print(id(x))   # Something like 140234866534400
    print(id(y))   # Same number — same object
    ```

=== "C"

    ```c
    int x = 42;
    int *p = &x;   // p holds the ADDRESS of x

    printf("x = %d\n", x);     // 42
    printf("&x = %p\n", &x);   // Something like 0x7ffd5e8a3b2c (address of x)
    printf("p = %p\n", p);     // Same address
    printf("*p = %d\n", *p);   // 42 (dereference: read the value AT the address)

    *p = 100;                   // Write 100 to the address p points to
    printf("x = %d\n", x);     // 100 — x changed because p points to x
    ```

## The Two Operators: `&` and `*`

There are only two pointer operators. Learn these and you're halfway there:

| Operator | Name | What It Does | Python Analogy |
|----------|------|-------------|----------------|
| `&x` | Address-of | Gets the memory address of `x` | `id(x)` |
| `*p` | Dereference | Reads/writes the value at the address in `p` | Following a reference to get the object |

```c
int value = 42;
int *ptr = &value;   // ptr now holds the address of value

// Reading
int copy = *ptr;     // copy = 42 (read what ptr points to)

// Writing
*ptr = 99;           // value is now 99 (write through the pointer)
```

!!! note "The `*` Has Two Meanings"
    In a declaration, `int *p` means "p is a pointer to an int." In an expression, `*p` means "dereference p — access the value it points to." Same symbol, different context. This confuses everyone at first.

## Pointer Types

Every pointer has a type that tells the compiler what kind of data it points to:

```c
int *ip;        // Pointer to an int
char *cp;       // Pointer to a char
__u32 *u32p;    // Pointer to a __u32
void *vp;       // Pointer to "anything" (generic pointer)
```

The type matters because it determines how the pointer dereferences. An `int *` reads 4 bytes when you dereference it. A `char *` reads 1 byte. A `void *` cannot be dereferenced directly — you must cast it first.

=== "Python"

    ```python
    # Python doesn't care — everything is a reference
    x = 42
    y = "hello"
    items = [x, y]  # A list can hold references to any type
    ```

=== "C"

    ```c
    int x = 42;
    char *msg = "hello";

    // void* is the "I don't know the type" pointer — like Python's generality
    void *generic = &x;
    int value = *(int *)generic;  // Must cast before dereferencing

    generic = msg;                // Can point to anything
    char first = *(char *)generic;  // Must cast to read
    ```

!!! tip "void* in eBPF"
    Many BPF helper functions take `void *` parameters because they work with generic data. For example, `bpf_map_lookup_elem()` returns a `void *` that you must cast to your map's value type. You'll see this pattern constantly.

## Stack vs Heap

Python manages memory automatically. C gives you two memory regions, and in eBPF you only get one of them.

### In Regular C

```
Stack (automatic)          Heap (dynamic)
├── Local variables        ├── malloc'd memory
├── Function arguments     ├── Must be free'd manually
├── Fixed size (~8 MB)     ├── Large, flexible
└── Freed automatically    └── Memory leaks if you forget
    when function returns
```

### In eBPF

```
Stack (only option)        Heap
├── Local variables        ├── NOT AVAILABLE
├── Limited to 512 bytes   ├── No malloc() in eBPF
├── Freed automatically    └── Use BPF maps for persistent storage
└── Must be careful about
    large structs
```

=== "Python"

    ```python
    # Python handles all memory automatically
    def process():
        data = [0] * 10000  # Python allocates, GC frees it later
        return data          # No problem returning large objects
    ```

=== "C"

    ```c
    // In regular C:
    void process() {
        int stack_array[100];         // On the stack — automatic
        int *heap_array = malloc(100 * sizeof(int));  // On the heap — manual

        free(heap_array);  // You must free heap memory
    }  // stack_array is freed automatically here

    // In eBPF:
    SEC("xdp")
    int process_packet(struct xdp_md *ctx) {
        __u32 key = 0;               // On the stack — OK
        struct event data = {};       // On the stack — OK if struct is small
        // malloc() does not exist here — compilation would fail
        return XDP_PASS;
    }
    ```

!!! warning "The 512-Byte Stack Limit"
    eBPF programs have a 512-byte stack limit. If you declare a local struct that's 600 bytes, the verifier will reject your program. For larger data, use BPF maps (covered in Part 2) or per-CPU arrays.

## NULL Pointers

A NULL pointer is a pointer that points to nothing. Dereferencing NULL is the most common crash in C programs.

=== "Python"

    ```python
    x = None
    x.something  # AttributeError — Python catches this

    # In a dictionary lookup:
    d = {"a": 1}
    val = d.get("b")  # Returns None, doesn't crash
    if val is not None:
        print(val)
    ```

=== "C"

    ```c
    int *p = NULL;    // p points to nothing
    // int x = *p;    // CRASH: segmentation fault (or kernel panic in eBPF)

    // Always check for NULL before dereferencing
    if (p != NULL) {
        int x = *p;   // Safe
    }
    ```

In eBPF, NULL checks are not just good practice — the verifier **requires** them. When you look up a value in a BPF map, the lookup can return NULL if the key doesn't exist. The verifier will reject your program if you dereference the result without checking for NULL first.

```c
// This pattern appears in EVERY eBPF program that uses maps
__u64 *count = bpf_map_lookup_elem(&my_map, &key);
if (!count) {        // NULL check — verifier requires this
    return 0;
}
*count += 1;         // Safe to dereference after the check
```

## Pointer Arithmetic

You can add integers to pointers. When you do, the pointer moves by that many **elements** (not bytes). This is how you navigate through arrays and packet data.

=== "Python"

    ```python
    data = [10, 20, 30, 40, 50]

    # Access by index
    first = data[0]   # 10
    third = data[2]   # 30
    ```

=== "C"

    ```c
    int data[] = {10, 20, 30, 40, 50};
    int *p = data;     // p points to the first element

    int first = *p;        // 10 (dereference: value at p)
    int second = *(p + 1); // 20 (move 1 int forward, dereference)
    int third = *(p + 2);  // 30 (move 2 ints forward, dereference)

    // Equivalent using array syntax
    int also_third = p[2]; // 30 — p[n] is just *(p + n)
    ```

The key insight: `p + 1` does NOT add 1 byte. It adds `sizeof(int)` bytes (4 bytes). The pointer type determines the step size.

```c
char *cp = (char *)some_address;
cp + 1;    // Moves 1 byte (sizeof(char) = 1)

int *ip = (int *)some_address;
ip + 1;    // Moves 4 bytes (sizeof(int) = 4)

__u64 *u64p = (__u64 *)some_address;
u64p + 1;  // Moves 8 bytes (sizeof(__u64) = 8)
```

### Pointer Arithmetic in eBPF Packet Parsing

This is where pointer arithmetic becomes essential. Packet data is a continuous block of bytes, and you navigate through headers using pointer offsets:

```c
SEC("xdp")
int parse_packet(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Ethernet header starts at the beginning
    struct ethhdr *eth = data;

    // IP header starts right after Ethernet header
    struct iphdr *ip = data + sizeof(struct ethhdr);

    // CRITICAL: bounds check — verifier requires this
    if ((void *)(ip + 1) > data_end) {
        return XDP_DROP;
    }

    // Now safe to read IP header fields
    __u32 src = ip->saddr;

    return XDP_PASS;
}
```

!!! warning "Bounds Checking Is Mandatory"
    In regular C, accessing memory out of bounds is undefined behavior — your program might crash, might corrupt data, or might appear to work fine. In eBPF, the verifier performs static analysis to prove that every pointer access is within bounds. If it can't prove it, your program won't load. This makes eBPF much safer than regular C, but you must write the bounds checks explicitly.

## Pointers to Structs: The `->` Operator

When you have a pointer to a struct, use `->` to access its fields (instead of `.`):

=== "Python"

    ```python
    class Packet:
        def __init__(self):
            self.src_port = 8080
            self.dst_port = 443

    pkt = Packet()
    print(pkt.src_port)   # 8080 — always use dot notation
    ```

=== "C"

    ```c
    struct packet {
        __u16 src_port;
        __u16 dst_port;
    };

    struct packet pkt = {8080, 443};
    struct packet *ptr = &pkt;

    // Direct access uses dot
    printf("%d\n", pkt.src_port);    // 8080

    // Pointer access uses arrow
    printf("%d\n", ptr->src_port);   // 8080

    // ptr->src_port is shorthand for (*ptr).src_port
    ```

In eBPF, you almost always work with pointers to structs (because you're pointing into packet data or map values), so `->` is far more common than `.`:

```c
struct iphdr *ip = /* ... */;
__u8 protocol = ip->protocol;   // Arrow because ip is a pointer
__u32 src = ip->saddr;          // Arrow
```

## Python's `id()` as a Mental Model

If the pointer concept still feels abstract, think of Python's `id()`:

```python
x = [1, 2, 3]
print(id(x))        # 140234866534400 — the memory address

# In C, a pointer IS this address stored in a variable:
# int *p = 140234866534400;  (conceptually)

y = x                # y gets the same address
print(id(x) == id(y))  # True — they point to the same memory

# In C:
# int *q = p;  (q gets a copy of p's address)
```

The difference is that Python never lets you manipulate addresses directly. C does, and that's both its power and its danger.

## Common Pointer Pitfalls

### 1. Dangling Pointers
```c
int *get_value() {
    int x = 42;
    return &x;    // BUG: x is destroyed when function returns
}                 // The returned pointer points to freed stack memory
```

### 2. Uninitialized Pointers
```c
int *p;          // Points to random memory
*p = 42;         // CRASH: writing to a random address
```

### 3. Forgetting NULL Checks
```c
// In eBPF — the verifier catches this
__u64 *val = bpf_map_lookup_elem(&map, &key);
*val += 1;       // REJECTED by verifier — val might be NULL
```

### 4. Out-of-Bounds Access
```c
// In eBPF — the verifier catches this too
void *data = (void *)(long)ctx->data;
struct iphdr *ip = data + sizeof(struct ethhdr);
__u32 src = ip->saddr;  // REJECTED: no bounds check before access
```

!!! tip "The eBPF Verifier as a Safety Net"
    One of the remarkable things about eBPF is that the verifier catches pointer bugs that would silently corrupt memory in regular C. If you get a verifier rejection, it's usually telling you about a real bug — a missing NULL check, a missing bounds check, or an out-of-range access. Learn to read verifier errors; they're your friend.

## Exercises

1. **Address explorer**: Write a C program that declares an `int`, a `char`, and a `__u32`. Print the value of each, the address of each (`&`), and the size of each (`sizeof`). Predict which addresses will be close together and why.

2. **Pointer swap**: Write a function `void swap(int *a, int *b)` that swaps the values of two integers using pointers. Then write the Python equivalent and explain why Python doesn't need pointers for this (hint: tuple unpacking).

3. **Array traversal**: Create an array of 5 `__u32` values. Write a loop that prints each value using pointer arithmetic (not array indexing). Verify that each step moves by exactly 4 bytes.

4. **NULL safety drill**: Write a function that simulates an eBPF map lookup: it takes a key and returns NULL 50% of the time (use `rand()`). Call this function and correctly handle the NULL case. Then write the Python equivalent using `dict.get()`.

5. **Stack size calculator**: Declare variables of types `__u8`, `__u16`, `__u32`, `__u64`, and a struct containing all four. Print the total stack bytes used. How close are you to eBPF's 512-byte limit? How many of these structs could you declare before hitting the limit?
