from pwn import *
context(arch='amd64', os='linux', log_level='debug')
#s=process("../dist/pwn")
s=remote("8.130.35.16",55001)
for i in range(100):
    s.recvuntil(b"====\n")
    a=int(s.recvuntil(b"+")[:-1])
    b=int(s.recvuntil(b"=")[:-1])
    #print(f"{a}+{b}={a+b}")
    s.sendline(str(a+b).encode())
s.interactive()