from pwn import *
from Crypto.Util.number import *
io = remote('0.0.0.0',10002)
io.recvuntil(b'key:\n')
pub = eval(io.recvline())
io.recvuntil(b'>')
msg = long_to_bytes(bytes_to_long(b'0xGame')+pub[0]-1)
io.sendline(msg)
io.recvuntil(b'r=')
r = int(io.recvline())
io.recvuntil(b's=')
s = int(io.recvline())
io.recvuntil(b'flag.\n')
io.sendline(str(r).encode())
io.sendline(str(s).encode())
io.interactive()
io.close()
