#part 1:get data

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

'''
#part 2:find key
from Crypto.Util.number import *

m = b'test'
m = bytes_to_long(m)
n=97914749446436063122542581376873112820400732267124998400088179058780712855378248201542023213009277089224170180542304344638059090556781844777641757174279080863658472878763702075705376304717343862101956239090701126225622317784075619757963099253602226642056966461019740454740445226152574361794251236011891077789
c=73133825445675329950286077126832004352164006658709453405485979363609175208129785294437379266100324978770868694885347204515053234232666436453863941132493106687387106354265743735994029551983269772204386433432638435914078485461320417024614354676213557287698752845797412775400104995650602775848941301838035593870

e = 65537

dbin = ''
with open('data.txt','r') as f:
	for i in range(1023):#私钥位数不同可能要判断的数量不同
		m_ = int(f.readline())
		h = (inverse(m,n)*m_)%n
		test = pow(c,2**i,n)
		#print(f'h={h}\nt={pow(c,2*(i),n)}')
		if h == test:
			dbin += '0'
		elif h == inverse(test,n):
			dbin += '1'

d = eval('0b'+dbin[::-1])#校验
if (pow(c,d,n)==m):
	print(d)
'''