# Chapter 5: Control Flow & Functions

Control flow in C will feel familiar — you have `if`, `else`, `for`, `while`, and `switch`. The syntax is different from Python (braces instead of colons, explicit comparisons), but the logic is the same. Functions work similarly too, with one critical difference: C requires explicit type declarations for parameters and return values.

The eBPF twist is that loops must have **provable bounds**. The verifier rejects any loop it cannot prove terminates, which means unbounded `while` loops and many `for` loops are not allowed. This chapter teaches the patterns that work.

## Conditionals: if, else, else if

=== "Python"

    ```python
    x = 42

    if x > 100:
        print("large")
    elif x > 10:
        print("medium")
    else:
        print("small")
    ```

=== "C"

    ```c
    int x = 42;

    if (x > 100) {
        printf("large\n");
    } else if (x > 10) {
        printf("medium\n");
    } else {
        printf("small\n");
    }
    ```

Key differences:

- Conditions must be in **parentheses**: `if (x > 10)` not `if x > 10`
- Blocks use **curly braces** `{}` not colons
- `elif` becomes `else if` (two words)
- The condition does not need to be boolean — any non-zero value is "true"

### Truthiness in C

In Python, you have explicit `True` and `False`. In C, zero is false and **any non-zero value is true**:

```c
int x = 42;
if (x) {
    // This executes because 42 is non-zero (true)
}

int y = 0;
if (y) {
    // This does NOT execute because 0 is false
}

void *ptr = NULL;  // NULL is typically 0
if (ptr) {
    // Does not execute — NULL/0 is false
}
if (!ptr) {
    // Executes — !NULL is true
}
```

!!! tip "The eBPF NULL Check Pattern"
    This is why you see `if (!ptr)` everywhere in eBPF code. It's checking if a pointer is NULL:
    ```c
    __u64 *val = bpf_map_lookup_elem(&my_map, &key);
    if (!val) {           // Same as: if (val == NULL)
        return XDP_DROP;  // Key not found
    }
    // val is valid here
    ```

### Comparison Operators

| Python | C | Meaning |
|--------|---|---------|
| `==` | `==` | Equal |
| `!=` | `!=` | Not equal |
| `<` | `<` | Less than |
| `>` | `>` | Greater than |
| `<=` | `<=` | Less or equal |
| `>=` | `>=` | Greater or equal |
| `and` | `&&` | Logical AND |
| `or` | `\|\|` | Logical OR |
| `not` | `!` | Logical NOT |

!!! warning "Assignment vs Comparison"
    In C, `=` is assignment and `==` is comparison. This is a common bug:
    ```c
    if (x = 5) {  // BUG: assigns 5 to x, then tests if 5 is true (it is)
        // Always executes!
    }

    if (x == 5) {  // Correct: tests if x equals 5
        // Executes only if x is 5
    }
    ```
    Modern compilers warn about this, but it's still a common mistake.

## Switch Statements

Switch is C's version of pattern matching (sort of). It's often cleaner than a chain of `if-else if` when comparing one value against many constants:

=== "Python"

    ```python
    # Python 3.10+ has match statement
    protocol = 6

    match protocol:
        case 1:
            print("ICMP")
        case 6:
            print("TCP")
        case 17:
            print("UDP")
        case _:
            print("Unknown")
    ```

=== "C"

    ```c
    int protocol = 6;

    switch (protocol) {
        case 1:
            printf("ICMP\n");
            break;
        case 6:
            printf("TCP\n");
            break;
        case 17:
            printf("UDP\n");
            break;
        default:
            printf("Unknown\n");
            break;
    }
    ```

!!! warning "Fallthrough Behavior"
    Without `break`, execution falls through to the next case:
    ```c
    switch (x) {
        case 1:
            printf("one\n");
            // No break — falls through!
        case 2:
            printf("two\n");
            break;
    }
    // If x is 1, prints "one" then "two"
    ```
    This is sometimes intentional (to handle multiple cases the same way) but often a bug.

### Switch in eBPF

Switch statements are common in eBPF for handling different packet types:

```c
SEC("xdp")
int classify_packet(struct xdp_md *ctx) {
    // ... parse to get protocol ...
    __u8 protocol = ip->protocol;

    switch (protocol) {
        case IPPROTO_TCP:  // 6
            return handle_tcp(ctx);
        case IPPROTO_UDP:  // 17
            return handle_udp(ctx);
        case IPPROTO_ICMP: // 1
            return XDP_PASS;
        default:
            return XDP_DROP;
    }
}
```

## Loops: for, while, do-while

### for Loops

=== "Python"

    ```python
    # Iterate over range
    for i in range(5):
        print(i)

    # Iterate over collection
    for item in items:
        process(item)
    ```

=== "C"

    ```c
    // Classic C for loop: init; condition; update
    for (int i = 0; i < 5; i++) {
        printf("%d\n", i);
    }

    // Iterate over array (no iterator syntax)
    int items[] = {1, 2, 3, 4, 5};
    int len = sizeof(items) / sizeof(items[0]);
    for (int i = 0; i < len; i++) {
        process(items[i]);
    }
    ```

The `for` loop has three parts: `for (init; condition; update)`:

- **init**: Runs once before the loop starts
- **condition**: Checked before each iteration; loop continues while true
- **update**: Runs after each iteration

### while Loops

=== "Python"

    ```python
    count = 0
    while count < 10:
        print(count)
        count += 1
    ```

=== "C"

    ```c
    int count = 0;
    while (count < 10) {
        printf("%d\n", count);
        count++;
    }
    ```

### do-while Loops

C has a loop that Python lacks: `do-while`, which always executes at least once:

```c
int count = 0;
do {
    printf("%d\n", count);
    count++;
} while (count < 10);

// Contrast with while: if count started at 10,
// while loop would execute 0 times
// do-while loop would execute 1 time
```

### break and continue

```c
for (int i = 0; i < 100; i++) {
    if (i == 5) {
        continue;  // Skip rest of this iteration, go to next i
    }
    if (i == 10) {
        break;     // Exit the loop entirely
    }
    printf("%d\n", i);
}
// Prints: 0, 1, 2, 3, 4, 6, 7, 8, 9
```

## Loops in eBPF: The Bounded Loop Requirement

Here's where eBPF differs from regular C. The verifier must prove that every loop terminates. It does this by analyzing the loop and checking that the iteration count has a known upper bound.

### Loops the Verifier Accepts

```c
// ✓ Classic bounded for loop
#define MAX_ITEMS 100
for (int i = 0; i < MAX_ITEMS; i++) {
    // Verifier knows this runs at most 100 times
}

// ✓ Loop with early exit (still bounded by MAX)
for (int i = 0; i < MAX_ITEMS; i++) {
    if (some_condition) {
        break;  // OK — exits early, still bounded
    }
}

// ✓ Bounded while loop (kernel 5.3+)
int i = 0;
while (i < MAX_ITEMS) {
    i++;
    // Body here
}
```

### Loops the Verifier Rejects

```c
// ✗ Unbounded while — verifier can't prove termination
while (ptr != NULL) {
    ptr = ptr->next;  // How many iterations? Unknown!
}

// ✗ Loop bound from runtime value
int n = get_packet_length();
for (int i = 0; i < n; i++) {
    // n is unknown at verify time — rejected
}

// ✗ Infinite loop
while (1) {
    // Never terminates — rejected
}
```

### The bpf_loop() Helper (Kernel 5.17+)

For cases where you need a loop with a runtime-determined count, use `bpf_loop()`:

```c
static int process_one(u32 index, void *ctx) {
    // Process one iteration
    // Return 0 to continue, 1 to stop
    return 0;
}

SEC("xdp")
int my_program(struct xdp_md *ctx) {
    int count = get_count();  // Runtime value

    // bpf_loop calls process_one up to 'count' times
    // The kernel guarantees it terminates
    bpf_loop(count, process_one, NULL, 0);

    return XDP_PASS;
}
```

!!! tip "Loop Unrolling with #pragma"
    For small, fixed iteration counts, the compiler can unroll the loop:
    ```c
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        // Compiler generates 4 copies of this code, no actual loop
    }
    ```
    This is sometimes necessary for the verifier to accept your code, especially for packet parsing where you need to check multiple bytes.

## Functions

### Function Declarations and Definitions

=== "Python"

    ```python
    def add(a: int, b: int) -> int:
        return a + b

    result = add(3, 4)  # 7
    ```

=== "C"

    ```c
    // Function definition — parameter and return types required
    int add(int a, int b) {
        return a + b;
    }

    int result = add(3, 4);  // 7
    ```

C functions require:

- **Return type** before the function name (`int add`)
- **Parameter types** for each parameter (`int a, int b`)
- **Return statement** for non-void functions

### void — No Return Value

```c
// Function that returns nothing
void print_number(int n) {
    printf("%d\n", n);
    // No return statement needed (or: return;)
}

// Function that takes no parameters
int get_magic_number(void) {  // 'void' means no parameters
    return 42;
}
```

### Function Prototypes (Forward Declarations)

In C, functions must be declared before use. If you define functions out of order, you need a **prototype**:

```c
// Prototype — tells compiler the function exists
int add(int a, int b);

int main() {
    int x = add(3, 4);  // OK — compiler knows add exists
    return 0;
}

// Definition — the actual implementation
int add(int a, int b) {
    return a + b;
}
```

### Functions in eBPF: static inline

eBPF programs have restrictions on function calls. Until kernel 5.10, you couldn't call regular functions from eBPF — all code had to be in the main function or inlined.

**`static inline`** tells the compiler to insert the function's code at each call site, avoiding an actual function call:

```c
// static inline — code is copied to each call site
static inline __u16 get_port(struct tcphdr *tcp) {
    return bpf_ntohs(tcp->dest);
}

SEC("xdp")
int my_program(struct xdp_md *ctx) {
    // When compiled, get_port's code is inserted here
    __u16 port = get_port(tcp);
    // ...
}
```

!!! note "BPF-to-BPF Calls (Kernel 5.10+)"
    Modern kernels support actual function calls between BPF functions, but `static inline` is still the common pattern because:

    1. It works on older kernels
    2. No function call overhead
    3. The verifier can better track values across inlined code

### Passing by Value vs Passing by Pointer

C passes arguments **by value** — the function gets a copy:

```c
void double_it(int x) {
    x = x * 2;  // Modifies the local copy
}

int a = 5;
double_it(a);
printf("%d\n", a);  // Still 5! The original wasn't changed.
```

To modify the original, pass a pointer:

```c
void double_it(int *x) {
    *x = *x * 2;  // Modifies the value at the address
}

int a = 5;
double_it(&a);     // Pass address of a
printf("%d\n", a);  // 10 — the original was changed
```

This is why Python's mutable objects (lists, dicts) seem to pass "by reference" — you're passing a reference (pointer) to the object, not the object itself.

## The Ternary Operator

A compact form of `if-else` that returns a value:

=== "Python"

    ```python
    x = 10
    result = "big" if x > 5 else "small"
    ```

=== "C"

    ```c
    int x = 10;
    char *result = (x > 5) ? "big" : "small";
    // condition ? value_if_true : value_if_false
    ```

Common in eBPF for compact conditional returns:

```c
return (proto == IPPROTO_TCP) ? handle_tcp() : XDP_PASS;
```

## Goto — When It's Appropriate

`goto` is generally avoided in modern programming, but it has one legitimate use case: **error handling and cleanup** in C. In eBPF, you'll see it for common exit paths:

```c
SEC("xdp")
int parse_packet(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        goto drop;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        goto drop;

    // Process packet...
    return XDP_PASS;

drop:
    return XDP_DROP;
}
```

This avoids duplicating the `return XDP_DROP` statement and makes the flow clearer.

## Exercises

1. **Switch protocol handler**: Write a function that takes an IP protocol number and returns a string name ("TCP", "UDP", "ICMP", "Unknown"). Use a switch statement.

2. **Bounded loop practice**: Write a loop that sums an array of 10 integers. First write it the normal way, then add `#pragma unroll` and compile with `-O2` to see the difference.

3. **Function pointers**: Write a function that takes two integers and a function pointer, then calls the function with those integers. Create `add` and `multiply` functions to test it.

4. **Early return vs goto**: Refactor this pseudocode two ways — once with early returns, once with goto:
    ```
    parse ethernet header
    if fail, drop
    parse ip header  
    if fail, drop
    parse tcp header
    if fail, drop
    process packet
    ```

5. **Static inline helper**: Create a `static inline` function that extracts the PID from a `__u64 pid_tgid` value (upper 32 bits). Use it in a simulated eBPF program structure.

6. **Verifier-friendly loop**: Write a loop that iterates through a fixed-size array and breaks early if it finds a zero value. Ensure it would pass the eBPF verifier.

7. **Python comparison**: Implement the same logic in both Python and C: a function that takes a protocol number and port, returns "allowed" if TCP on port 80 or 443, "denied" otherwise.
