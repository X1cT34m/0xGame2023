from pwn import *
from hashlib import sha1
from Crypto.Util.number import *

context(os='linux', arch='amd64', log_level='debug')
h = bytes_to_long(sha1(b'test').digest())
s = []
r = []

io = remote('0.0.0.0',10002)

def Sign(target):
	target.sendafter(b'>',b'S')
	target.sendafter(b'>',b'test')
	target.recvuntil(b's = ')
	s_ = int(target.recvline())
	target.recvuntil(b'r = ')
	r_ = int(target.recvline())
	s.append(s_)
	r.append(r_)

io.recvuntil(b'q=')
q=int(io.recvline())
io.recvuntil(b'g=')
g=int(io.recvline())
io.recvuntil(b'y=')
y=int(io.recvline())

for i in range(10):
	Sign(io)
io.close()

print(f'q={q}')
print(f'h={h}')
print(f'r={r}')
print(f's={s}')