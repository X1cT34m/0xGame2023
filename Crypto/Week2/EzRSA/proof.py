from pwn import *
import itertools
import string
import hashlib
from Crypto.Util.number import *

def proof(io):
    io.recvuntil(b"XXXX+")
    suffix = io.recv(16).decode("utf8")
    io.recvuntil(b"== ")
    cipher = io.recvline().strip().decode("utf8")
    for i in itertools.product(string.ascii_letters+string.digits, repeat=4):
        x = "{}{}{}{}".format(i[0],i[1],i[2],i[3])
        proof=hashlib.sha256((x+suffix.format(i[0],i[1],i[2],i[3])).encode()).hexdigest()
        if proof == cipher:
            break
    print(x)
    io.sendlineafter(b"XXXX:",x.encode())

io = remote('43.139.107.237',10006)
proof(io)
io.interactive()