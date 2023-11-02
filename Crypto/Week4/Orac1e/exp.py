from pwn import *
from base64 import b64encode,b64decode
#context(log_level='debug')
io = remote('0.0.0.0',10002)

size = 16

def Orac1e(payload,index):
    data = b64encode(payload)
    io.sendafter(b'>',data)
    tmp = io.recvline()
    if tmp == b' Data update\n':
        print(index)
        return 1
    else:
        return 0

def Oracle(BIV,BC):
    D = []
    for index in range(15,-1,-1):
        I = [0 for _ in range(index)]
        for i in range(256):
            if D == []:
                CIV = bytes(I)+bytes([i])
            else:     
                CIV = bytes(I)+bytes([i])+xor(D,16-index)
            assert len(CIV) == 16
            payload = CIV+BC
            if Orac1e(payload,index):
                D.insert(0,(i^(16-index)))
                break
    return xor(D,BIV)

def Attack(c):
    Block_count = len(c)//16
    print(f'Block_count={Block_count}')
    iv = c[0:16]
    m = b''
    for i in range(1,Block_count):
        m += Oracle(c[size*(i-1):size*i],c[size*i:size*(i+1)])
        #print(m)
    return m
    
io.recvline()
c = io.recvline()[:-1]
c = b64decode(c)
print(Attack(c))

