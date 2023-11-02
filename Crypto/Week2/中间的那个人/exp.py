from Crypto.Util.number import *
from Crypto.Cipher import AES
from hashlib import sha256
g=2
p=250858685680234165065801734515633434653
Bob=33067794433420687511728239091450927373
Alice=235866450680721760403251513646370485539
'''
G = GF(p)
g = G(g)
y = G(Alice)
x = discrete_log(y,g)

'''
x = 3992780394
key = pow(Bob,x,p)
key = sha256(long_to_bytes(key)).digest()
iv = b"0xGame0xGameGAME"
aes = AES.new(key, AES.MODE_CBC, iv)
enc=b's\x04\xbc\x8bT6\x846\xd9\xd6\x83 y\xaah\xde@\xc9\x17\xdc\x04v\x18\xef\xcf\xef\xc5\xfd|\x0e\xca\n\xbd#\x94{\x8e[.\xe8\xe1GU\xfa?\xda\x11w'

flag = aes.decrypt(enc)
print(flag)