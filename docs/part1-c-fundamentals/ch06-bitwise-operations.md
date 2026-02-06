# Chapter 6: Bitwise Operations

Network protocols are designed around bits and bytes, not high-level abstractions. TCP flags are individual bits in a byte. IP header lengths are encoded in 4-bit fields. Protocol numbers fit in a single byte. To parse and manipulate network data, you need to think at the bit level.

Python has bitwise operators, but you rarely use them in typical Python code. In C and eBPF, you use them constantly. This chapter gives you the fluency to read expressions like `(flags & TH_SYN) && !(flags & TH_ACK)` without pausing.

## Binary Representation Refresher

Before diving into operators, let's ensure the binary representation is clear:

```
Decimal     Binary          Hex
0           00000000        0x00
1           00000001        0x01
2           00000010        0x02
3           00000011        0x03
4           00000100        0x04
5           00000101        0x05
8           00001000        0x08
15          00001111        0x0F
16          00010000        0x10
255         11111111        0xFF
```

Each bit position represents a power of 2:

```
Bit position:    7    6    5    4    3    2    1    0
Power of 2:     128   64   32   16    8    4    2    1

Example: 77 = 64 + 8 + 4 + 1 = 01001101
```

In Python:

```python
>>> bin(77)
'0b1001101'
>>> 0b01001101
77
>>> hex(77)
'0x4d'
```

## The Six Bitwise Operators

| Operator | Name | Python | C | Description |
|----------|------|--------|---|-------------|
| `&` | AND | `a & b` | `a & b` | 1 if both bits are 1 |
| `\|` | OR | `a \| b` | `a \| b` | 1 if either bit is 1 |
| `^` | XOR | `a ^ b` | `a ^ b` | 1 if bits are different |
| `~` | NOT | `~a` | `~a` | Flips all bits |
| `<<` | Left shift | `a << n` | `a << n` | Shift bits left by n |
| `>>` | Right shift | `a >> n` | `a >> n` | Shift bits right by n |

The operators are identical in Python and C — the logic is the same.

## AND (`&`): Testing and Masking

AND compares each bit: the result is 1 only if **both** input bits are 1.

```
    10101100  (172)
  & 00001111  (15, the "mask")
  ----------
    00001100  (12)
```

### Use Case 1: Testing If a Bit Is Set

To check if a specific bit is set, AND with a mask that has only that bit set:

=== "Python"

    ```python
    # TCP flags are bits in a byte
    TH_FIN = 0x01  # 00000001
    TH_SYN = 0x02  # 00000010
    TH_RST = 0x04  # 00000100
    TH_ACK = 0x10  # 00010000

    flags = 0x12  # SYN + ACK = 00010010

    if flags & TH_SYN:
        print("SYN flag is set")

    if flags & TH_ACK:
        print("ACK flag is set")

    if not (flags & TH_RST):
        print("RST flag is NOT set")
    ```

=== "C"

    ```c
    #define TH_FIN  0x01  // 00000001
    #define TH_SYN  0x02  // 00000010
    #define TH_RST  0x04  // 00000100
    #define TH_ACK  0x10  // 00010000

    __u8 flags = 0x12;  // SYN + ACK = 00010010

    if (flags & TH_SYN) {
        // SYN flag is set
    }

    if (flags & TH_ACK) {
        // ACK flag is set
    }

    if (!(flags & TH_RST)) {
        // RST flag is NOT set
    }
    ```

### Use Case 2: Extracting a Field

Some protocol fields pack multiple values into bytes. The IP header's first byte contains the version (high 4 bits) and header length (low 4 bits):

```c
__u8 first_byte = ip_header[0];  // e.g., 0x45

__u8 version = (first_byte >> 4) & 0x0F;  // Shift right 4, mask low 4 bits
// 0x45 >> 4 = 0x04, then & 0x0F = 0x04 (version 4)

__u8 ihl = first_byte & 0x0F;  // Just mask low 4 bits
// 0x45 & 0x0F = 0x05 (header length in 32-bit words)
```

## OR (`|`): Setting Bits

OR compares each bit: the result is 1 if **either** input bit is 1.

```
    10100000  (160)
  | 00001010  (10)
  ----------
    10101010  (170)
```

### Use Case: Setting Flags

```c
__u8 flags = 0;

// Set the SYN flag
flags = flags | TH_SYN;  // or: flags |= TH_SYN;
// flags is now 0x02

// Set the ACK flag too
flags |= TH_ACK;
// flags is now 0x12 (SYN + ACK)
```

## XOR (`^`): Toggling and Comparing

XOR compares each bit: the result is 1 if the bits are **different**.

```
    10101100  (172)
  ^ 00001111  (15)
  ----------
    10100011  (163)
```

### Use Case 1: Toggle Bits

```c
__u8 flags = 0x12;  // SYN + ACK

// Toggle the SYN flag (turn it off if on, on if off)
flags ^= TH_SYN;
// flags is now 0x10 (just ACK)

flags ^= TH_SYN;
// flags is back to 0x12 (SYN + ACK)
```

### Use Case 2: Check If Two Values Are Equal

XOR of identical values is zero:

```c
if ((a ^ b) == 0) {
    // a and b are equal
}
// Equivalent to: if (a == b)
```

### Use Case 3: Swap Without Temp Variable

```c
// Classic XOR swap trick
a ^= b;
b ^= a;
a ^= b;
// a and b are now swapped
```

## NOT (`~`): Flipping All Bits

NOT inverts every bit: 0 becomes 1, 1 becomes 0.

```
  ~ 00001111  (15)
  ----------
    11110000  (240, for 8-bit)
```

!!! warning "Signed vs Unsigned"
    The result of `~` depends on the type's size and signedness:
    ```c
    __u8 a = 0x0F;
    __u8 b = ~a;      // b = 0xF0 (240)

    int c = 0x0F;
    int d = ~c;       // d = 0xFFFFFFF0 (-16 if signed)
    ```

### Use Case: Clearing Bits

To clear specific bits, AND with the NOT of a mask:

```c
__u8 flags = 0x12;  // SYN + ACK

// Clear the SYN flag
flags = flags & ~TH_SYN;  // or: flags &= ~TH_SYN;
// ~TH_SYN = 0xFD = 11111101
// 0x12 & 0xFD = 0x10 (just ACK)
```

## Left Shift (`<<`): Multiply by Powers of 2

Shifting left by n positions multiplies by 2^n:

```
    00000101  (5)
 << 2
  ----------
    00010100  (20 = 5 × 4 = 5 × 2²)
```

### Use Case 1: Creating Bit Masks

```c
// Create a mask with bit n set
__u8 mask = 1 << 3;  // 00001000 (bit 3)
__u8 mask = 1 << 7;  // 10000000 (bit 7)

// Create a mask with low n bits set
__u8 mask = (1 << 4) - 1;  // 00010000 - 1 = 00001111
```

### Use Case 2: Constructing Multi-Byte Values

```c
// Build a 32-bit value from 4 bytes
__u8 b0 = 10, b1 = 0, b2 = 0, b3 = 1;
__u32 ip = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
// ip = 0x0A000001 = 167772161 = 10.0.0.1
```

## Right Shift (`>>`): Divide by Powers of 2

Shifting right by n positions divides by 2^n (truncating):

```
    00010100  (20)
 >> 2
  ----------
    00000101  (5 = 20 ÷ 4)
```

### Use Case: Extracting High Bytes

```c
// Extract PID from pid_tgid (upper 32 bits)
__u64 pid_tgid = bpf_get_current_pid_tgid();
__u32 pid = pid_tgid >> 32;  // Shift right 32 bits
__u32 tgid = pid_tgid & 0xFFFFFFFF;  // Mask low 32 bits
```

!!! note "Arithmetic vs Logical Shift"
    For unsigned types, `>>` always shifts in zeros (logical shift). For signed types, it may shift in copies of the sign bit (arithmetic shift). Always use unsigned types for bitwise operations to avoid surprises.

## Common Patterns in eBPF

### Pattern 1: Check TCP SYN Without ACK

```c
// A new connection starts with SYN set but ACK not set
if ((flags & TH_SYN) && !(flags & TH_ACK)) {
    // This is a SYN packet (connection initiation)
}
```

### Pattern 2: Extract PID and TGID

```c
__u64 pid_tgid = bpf_get_current_pid_tgid();
__u32 pid = pid_tgid >> 32;      // Upper 32 bits
__u32 tgid = (__u32)pid_tgid;    // Lower 32 bits (cast truncates)
```

### Pattern 3: Build IPv4 Address from Bytes

```c
// From network byte order (big-endian)
__u8 bytes[4] = {192, 168, 1, 1};
__u32 ip = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
```

### Pattern 4: Extract IP Header Fields

```c
struct iphdr *ip = /* ... */;

// Version and IHL are packed into the first byte
__u8 version = ip->version;  // Already extracted by struct
__u8 ihl = ip->ihl;          // Header length in 32-bit words

// Alternatively, from raw byte:
__u8 first = ((__u8 *)ip)[0];
__u8 version = first >> 4;
__u8 ihl = first & 0x0F;
```

### Pattern 5: Port Number Byte Swap

```c
// Network byte order is big-endian; x86 is little-endian
// bpf_ntohs converts network-to-host byte order
__u16 net_port = tcp->dest;       // Network byte order
__u16 host_port = bpf_ntohs(net_port);  // Host byte order

// Manual swap (for understanding):
__u16 host_port = ((net_port >> 8) & 0xFF) | ((net_port & 0xFF) << 8);
```

## Operator Precedence

Bitwise operators have lower precedence than comparison operators. This causes bugs:

```c
// WRONG — comparison happens first!
if (flags & TH_SYN == TH_SYN) {
    // Parsed as: flags & (TH_SYN == TH_SYN)
    // Which is: flags & 1 (true)
}

// RIGHT — use parentheses
if ((flags & TH_SYN) == TH_SYN) {
    // Correct: test if SYN bit is set
}

// Or simpler (non-zero is true):
if (flags & TH_SYN) {
    // SYN is set
}
```

!!! warning "Always Use Parentheses"
    When mixing bitwise and comparison operators, always use parentheses. Don't rely on remembering precedence rules.

## Python Practice: Bitwise Playground

Python is great for experimenting with bitwise operations:

```python
# Visualize operations
def show(name, value, bits=8):
    print(f"{name}: {value:3d} = {value:0{bits}b} = 0x{value:02X}")

a = 0b10101100
b = 0b00001111

show("a", a)
show("b", b)
show("a & b", a & b)
show("a | b", a | b)
show("a ^ b", a ^ b)
show("~a & 0xFF", ~a & 0xFF)  # Mask to 8 bits
show("a << 2", (a << 2) & 0xFF)
show("a >> 2", a >> 2)
```

## Exercises

1. **Flag checker**: Write a function that takes TCP flags as a byte and prints which flags are set (FIN, SYN, RST, PSH, ACK, URG). Use the standard flag values.

2. **IP builder**: Write code that takes 4 integers (0-255) representing an IPv4 address and combines them into a single `__u32` using bit shifts and OR.

3. **IP extractor**: Write the reverse — take a `__u32` IPv4 address and extract the four octets using shifts and masks.

4. **Bit counter**: Write a function that counts how many bits are set to 1 in a `__u32`. (Hint: loop through all 32 bits, or use the "Brian Kernighan trick": `n & (n-1)` clears the lowest set bit.)

5. **SYN-ACK detector**: Write an expression that returns true only if both SYN and ACK are set, but RST is not.

6. **Port swap**: Manually swap the bytes of a 16-bit port number using shifts and masks (simulating `bpf_ntohs`).

7. **Field packer**: Pack a 4-bit version number and a 4-bit header length into a single byte, then extract both values.

8. **Python-to-C translation**: Take this Python code and translate it to C:
    ```python
    def is_broadcast_mac(mac_bytes):
        return all(b == 0xFF for b in mac_bytes)
    ```
    Use bitwise operations in your C version.
