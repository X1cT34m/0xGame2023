from pwn import *
import itertools
import hashlib 
import string

def proof(io):
    io.recvuntil(b"XXXX+")
    suffix = io.recv(16).decode("utf8")
    io.recvuntil(b"== ")
    cipher = io.recvline().strip().decode("utf8")
    for i in itertools.product(string.ascii_letters+string.digits, repeat=4):
        x = f"{i[0]}{i[1]}{i[2]}{i[3]}"
        proof=hashlib.sha256((x+suffix).encode()).hexdigest()
        if proof == cipher: break
    print(x)
    io.sendlineafter(b"XXXX:",x.encode())

f = open('data.txt','a')
io = remote('43.139.107.237',10005)
proof(io)
io.recvuntil(b'>')
io.sendline(b'S')
io.recvuntil(b'>')
io.sendline(b'test')
n = int(io.recvline())
e = int(io.recvline())
c = int(io.recvline())
for i in range(1023):
    io.recvuntil(b'>')
    io.sendline(b'F')
    io.recvuntil(b'>')
    io.sendline(f'{c}'.encode())
    io.recvuntil(b'>')
    io.sendline(f'{i}'.encode())
    io.recvline()
    m_ = int(io.recvline())
    f.write(str(m_)+'\n')

io.close()
f.close()
print(f'n={n}')
print(f'c={c}')
#大概三分钟