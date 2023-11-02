from Crypto.Util.number import *
from secret import msg
import random

flag = b'0xGame{' + msg + b'}'

q = getPrime(80)
a,b= [random.randrange(1,q-1) for i in range(2)]

def add(P,Q):
	if P[0] != Q[0] and P[1] != Q[1]:
		t = ((Q[1]-P[1]) * inverse(Q[0]-P[0],q)) %q
	else:
		t = ((3*P[0]*P[0]+a) * inverse(2*P[1],q))%q

	x3 = t*t - P[0] - Q[0]
	y3 = t*(P[0] - x3) - P[1]
	return (x3%q, y3%q)

def mul(t, A, B=0):
    if not t: return B
    return mul(t//2, add(A,A), B if not t&1 else add(B,A) if B else A)

assert len(msg)%2==0
m1=bytes_to_long(msg[:len(msg)//2])
m2=bytes_to_long(msg[len(msg)//2:])

k = random.getrandbits(64)
G = (641322496020493855620384 , 437819621961768591577606)
K = mul(k,G)

M = (m1,m2)
r = random.getrandbits(16)

C_1 = add(M,mul(r,K))
C_2 = mul(r,G)

print(f'q={q}\na={a}\nb={b}\n')
print(f'G = {G}\nK = {K}\nC_1={C_1}\nC_2={C_2}')

'''
q=1139075593950729137191297
a=930515656721155210883162
b=631258792856205568553568

G = (641322496020493855620384, 437819621961768591577606)
K = (781988559490437792081406, 76709224526706154630278)
C_1=(55568609433135042994738, 626496338010773913984218)
C_2=(508425841918584868754821, 816040882076938893064041)
'''
