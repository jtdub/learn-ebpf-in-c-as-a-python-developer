# Chapter 4: Arrays & Strings

Arrays in C are fundamentally different from Python lists. A Python list is a dynamic, growable container that can hold objects of any type. A C array is a fixed-size, contiguous block of memory where every element has the same type and size, allocated at compile time.

In eBPF, you use arrays constantly: packet data is a byte array, process names are character arrays, and many BPF maps are essentially arrays. Understanding C arrays is essential for safe and efficient eBPF code.

## Python Lists vs C Arrays

=== "Python"

    ```python
    # Python lists: dynamic, heterogeneous, bounds-checked
    numbers = [10, 20, 30, 40, 50]
    numbers.append(60)          # Grows dynamically
    numbers[0] = "hello"        # Can hold any type
    print(numbers[100])         # IndexError — runtime check

    # List is an object with metadata
    import sys
    print(sys.getsizeof(numbers))  # 120 bytes (for 6 integers!)
    ```

=== "C"

    ```c
    // C arrays: fixed-size, homogeneous, no bounds checking
    int numbers[5] = {10, 20, 30, 40, 50};
    // numbers[5] = 60;         // Can't grow — compile error or corruption
    // numbers[0] = "hello";    // Type error — won't compile
    printf("%d\n", numbers[100]); // No error! Reads garbage (undefined behavior)

    // Array is just the raw data — no overhead
    printf("Size: %lu\n", sizeof(numbers));  // 20 bytes (5 × 4 bytes)
    ```

!!! warning "No Bounds Checking in C"
    This is the single most important difference. In Python, accessing `list[100]` on a 5-element list raises `IndexError`. In C, accessing `array[100]` on a 5-element array silently reads or writes memory beyond the array — potentially corrupting other data or crashing the program. In eBPF, the verifier enforces bounds checks for you, but you must write them explicitly.

## Declaring and Initializing Arrays

```c
// Declaration with size
int values[5];                    // 5 uninitialized integers (garbage!)

// Declaration with initialization
int values[5] = {1, 2, 3, 4, 5}; // All 5 values initialized

// Partial initialization — rest are zero
int values[5] = {1, 2};          // {1, 2, 0, 0, 0}

// Zero initialization — all zeros
int values[5] = {0};             // {0, 0, 0, 0, 0}
int values[5] = {};              // Same — all zeros (C99+)

// Size from initializer — compiler counts elements
int values[] = {1, 2, 3, 4, 5}; // Size is 5, inferred from initializer
```

!!! tip "Always Initialize Arrays"
    In Python, you can't have an uninitialized variable. In C, uninitialized arrays contain whatever garbage was in that memory. Always initialize with `= {0}` or `= {}` unless you're immediately filling in all values. In eBPF, reading uninitialized stack memory is rejected by the verifier.

## Array Indexing

Array indexing in C looks identical to Python:

```c
int arr[5] = {10, 20, 30, 40, 50};

int first = arr[0];   // 10
int third = arr[2];   // 30
int last = arr[4];    // 50

arr[1] = 200;         // Modify second element
```

But remember: C does **not** check bounds. `arr[-1]` and `arr[100]` compile and run, producing undefined behavior.

### Negative Indexing

Python supports negative indices (`arr[-1]` for the last element). C does not:

=== "Python"

    ```python
    arr = [10, 20, 30, 40, 50]
    print(arr[-1])   # 50 — last element
    print(arr[-2])   # 40 — second to last
    ```

=== "C"

    ```c
    int arr[5] = {10, 20, 30, 40, 50};
    // int last = arr[-1];   // UNDEFINED BEHAVIOR — reads memory before array

    // To get the last element:
    int last = arr[4];                    // Explicit index
    int last = arr[sizeof(arr)/sizeof(arr[0]) - 1];  // Computed
    ```

## Arrays and Pointers: The Connection

In C, an array name is essentially a pointer to its first element. This is called **array decay**:

```c
int arr[5] = {10, 20, 30, 40, 50};

int *ptr = arr;      // arr "decays" to a pointer to arr[0]
int *also = &arr[0]; // Explicitly taking address of first element

printf("%d\n", *ptr);      // 10
printf("%d\n", *(ptr+1));  // 20
printf("%d\n", ptr[2]);    // 30 — ptr[n] is same as *(ptr+n)
```

This means array indexing `arr[i]` is secretly pointer arithmetic `*(arr + i)`:

```c
// These are all equivalent
arr[3]
*(arr + 3)
*(3 + arr)
3[arr]          // Yes, this compiles and works (don't do this)
```

!!! note "Python Comparison"
    In Python, `list[i]` is method call that performs bounds checking and returns an object reference. In C, `arr[i]` is syntactic sugar for pointer arithmetic — it computes an address and reads bytes from that location with no safety checks.

## Multidimensional Arrays

C supports multidimensional arrays, which are stored as contiguous memory in **row-major order**:

```c
// 2D array: 3 rows, 4 columns
int matrix[3][4] = {
    {1, 2, 3, 4},      // Row 0
    {5, 6, 7, 8},      // Row 1
    {9, 10, 11, 12}    // Row 2
};

printf("%d\n", matrix[1][2]);  // 7 (row 1, column 2)

// Memory layout: all 12 integers are contiguous
// [1][2][3][4][5][6][7][8][9][10][11][12]
// Row 0       Row 1       Row 2
```

In eBPF, you rarely need multidimensional arrays — packet data is a flat byte array, and BPF maps provide more flexible data structures.

## Strings Are Character Arrays

C has no built-in string type. A "string" is just an array of `char` terminated by a **null byte** (`\0`):

=== "Python"

    ```python
    name = "hello"
    print(len(name))       # 5
    print(name[0])         # 'h'
    name = name + " world" # Creates new string (strings are immutable)
    ```

=== "C"

    ```c
    char name[] = "hello";  // Array of 6 chars: {'h','e','l','l','o','\0'}

    printf("%lu\n", sizeof(name));  // 6 — includes null terminator
    printf("%lu\n", strlen(name));  // 5 — string length (excludes null)
    printf("%c\n", name[0]);        // 'h'

    name[0] = 'j';                  // Mutable — now "jello"
    // name = "world";              // ERROR: can't reassign array
    ```

!!! warning "The Null Terminator"
    Every C string must end with `\0`. Functions like `strlen()`, `printf("%s")`, and `strcpy()` read until they find this null byte. If you forget it, they keep reading memory until they find a zero byte somewhere — potentially exposing sensitive data or crashing.

### String Literals vs Character Arrays

```c
// String literal — stored in read-only memory
char *literal = "hello";
// literal[0] = 'j';  // CRASH: trying to modify read-only memory

// Character array — stored on stack, modifiable
char array[] = "hello";
array[0] = 'j';        // OK — array is in writable memory

// Array with explicit size
char buffer[32] = "hello";  // 32 bytes allocated, only 6 used
                             // Remaining bytes are zero
```

## String Functions (and Why eBPF Can't Use Them)

Standard C provides string functions in `<string.h>`:

```c
#include <string.h>

char src[] = "hello";
char dst[32];

strlen(src);              // 5 — length without null terminator
strcpy(dst, src);         // Copy src to dst
strncpy(dst, src, 31);    // Copy with max length (safer)
strcmp(src, "hello");     // 0 if equal, negative/positive if different
strcat(dst, " world");    // Append to dst
```

!!! warning "No Standard Library in eBPF"
    eBPF programs run in the kernel and cannot call standard library functions. No `strlen()`, no `strcpy()`, no `printf()`. The kernel provides BPF helpers like `bpf_probe_read_str()` for string operations and `bpf_printk()` for debugging output.

### eBPF String Handling

In eBPF, you work with strings as fixed-size character arrays:

```c
// Process name is stored in a fixed-size buffer
#define TASK_COMM_LEN 16

struct event {
    __u32 pid;
    char comm[TASK_COMM_LEN];  // Process name
};

SEC("kprobe/sys_execve")
int trace_exec(struct pt_regs *ctx) {
    struct event e = {};

    e.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));  // Kernel helper

    // Submit event to userspace...
    return 0;
}
```

## Bounds Checking: The Critical Difference

In Python, bounds checking is automatic. In C, you must do it yourself. In eBPF, the verifier requires you to prove every access is safe:

=== "Python"

    ```python
    data = bytes([0x01, 0x02, 0x03, 0x04, 0x05])

    # Safe — Python raises IndexError
    try:
        x = data[10]
    except IndexError:
        print("Out of bounds!")

    # Slicing is also safe
    chunk = data[2:100]  # Returns data[2:5], no error
    ```

=== "C"

    ```c
    // Regular C — programmer must check bounds
    __u8 data[5] = {0x01, 0x02, 0x03, 0x04, 0x05};
    size_t len = 5;
    size_t index = 10;

    // You must check before accessing
    if (index < len) {
        __u8 x = data[index];  // Safe
    } else {
        // Handle error
    }

    // In eBPF — verifier requires bounds checks
    SEC("xdp")
    int parse(struct xdp_md *ctx) {
        void *data = (void *)(long)ctx->data;
        void *data_end = (void *)(long)ctx->data_end;

        // Access first 5 bytes
        __u8 *ptr = data;

        // Verifier REQUIRES this check before accessing ptr[4]
        if (ptr + 5 > data_end)
            return XDP_DROP;

        __u8 fifth = ptr[4];  // Now verifier knows this is safe
        return XDP_PASS;
    }
    ```

!!! tip "The eBPF Bounds Check Pattern"
    You will write this pattern hundreds of times in eBPF:
    ```c
    if ((void *)(ptr + size) > data_end)
        return XDP_DROP;  // or handle error
    // Now safe to access ptr[0] through ptr[size-1]
    ```
    This is not optional — the verifier rejects programs without these checks.

## Arrays as Function Parameters

When you pass an array to a function, it decays to a pointer. The function doesn't know the array's size unless you pass it separately:

```c
// Function receives a pointer, not an array
void print_array(int *arr, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%d ", arr[i]);
    }
}

// Or equivalently (same thing):
void print_array(int arr[], size_t len) {
    // arr is still just a pointer here
    // sizeof(arr) would be sizeof(int*), not array size
}

int numbers[5] = {1, 2, 3, 4, 5};
print_array(numbers, 5);  // Pass array and its size
```

In Python, `len(list)` works because lists carry their size. In C, you must track and pass sizes explicitly.

## Variable-Length Arrays (VLAs)

C99 introduced variable-length arrays where the size is determined at runtime:

```c
void process(size_t n) {
    int arr[n];  // Size determined at runtime
    // ...
}
```

!!! danger "No VLAs in eBPF"
    Variable-length arrays are **not allowed** in eBPF programs. The verifier needs to know all stack allocations at compile time. You must use fixed-size arrays or BPF maps for dynamic storage.

    ```c
    // WRONG — verifier rejects this
    SEC("xdp")
    int bad_program(struct xdp_md *ctx) {
        int n = /* something */;
        char buffer[n];  // REJECTED — VLA not allowed
        return XDP_PASS;
    }

    // RIGHT — fixed-size array
    #define MAX_BUFFER 256
    SEC("xdp")
    int good_program(struct xdp_md *ctx) {
        char buffer[MAX_BUFFER] = {};  // OK — size known at compile time
        return XDP_PASS;
    }
    ```

## Common Array Pitfalls

### 1. Buffer Overflow

```c
char name[8];
strcpy(name, "Alexander");  // 10 chars (including \0) into 8-byte buffer!
// Corrupts memory beyond the array
```

### 2. Off-by-One Errors

```c
int arr[5];
for (int i = 0; i <= 5; i++) {  // BUG: should be i < 5
    arr[i] = i;  // arr[5] is out of bounds!
}
```

### 3. Forgetting the Null Terminator

```c
char buf[5];
buf[0] = 'h';
buf[1] = 'e';
buf[2] = 'l';
buf[3] = 'l';
buf[4] = 'o';
printf("%s\n", buf);  // Keeps printing garbage until it finds a \0
```

### 4. Confusing sizeof with strlen

```c
char str[] = "hello";
printf("%lu\n", sizeof(str));  // 6 — array size including \0
printf("%lu\n", strlen(str));  // 5 — string length excluding \0
```

## Exercises

1. **Bounds checker**: Write a function that takes an integer array and its size, and safely returns the element at a given index (or -1 if out of bounds). Compare to Python's list behavior.

2. **String length**: Implement your own `my_strlen()` function that counts characters until it finds `\0`. Test it on several strings.

3. **Array reversal**: Write a function that reverses an integer array in place (without creating a new array). Remember you need to pass the size explicitly.

4. **eBPF bounds pattern**: Write an eBPF-style bounds check for accessing the first 20 bytes of a packet. Show what happens if you try to access byte 21 without updating the check.

5. **String copy**: Implement a safe `my_strncpy(dst, src, n)` that copies at most `n-1` characters and always null-terminates. This is what `strncpy` should have been.

6. **2D array memory**: Create a 3x3 integer matrix and print the memory address of each element. Verify that the memory layout is contiguous in row-major order.

7. **Python struct comparison**: Use Python's `struct.pack()` to create a byte array equivalent to a C `char name[16]` containing "hello". Compare the binary representation to what C produces.
