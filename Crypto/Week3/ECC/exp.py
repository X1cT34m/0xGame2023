from Crypto.Util.number import *

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


q=1139075593950729137191297
a=930515656721155210883162
b=631258792856205568553568

G = (641322496020493855620384, 437819621961768591577606)
K = (781988559490437792081406, 76709224526706154630278)
C_1=(926699948475842085692652, 598672291835744938490461)
C_2=(919875062299924962858230, 227616977409545353942469)
k = 12515237792257199894
tmp = mul(k,C_2)
tmp = (tmp[0],-tmp[1])
M = add(C_1,tmp)


print(long_to_bytes(M[0])+long_to_bytes(M[1]))
