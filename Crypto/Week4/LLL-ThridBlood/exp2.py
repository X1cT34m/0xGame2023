from Crypto.Util.number import inverse
q=
h=
r=
s=
#填入数据就ok

A=[]
B=[]
M=[]

t = 120#填入k的大概位数，相当于一个上界
for i in range(len(r)):
    tmp = [0 for i in range(len(r)+2)]
    tmp[i] = q
    A.append(mod(r[i]*s[0]*inverse_mod(r[0]*s[i],q),q))
    B.append(mod((r[0]*h-r[i]*h)*inverse_mod(r[0]*s[i],q),q))
    M.append(tmp)

A.extend([1,0])
B.extend([0,2^(t)])
M.append(A)
M.append(B)
M = matrix(ZZ, M)
#构造矩阵
T = M.LLL()


s0 = s[0]
s1 = s[1]
r0 =r[0]
k = T[0][0]
x = inverse(r0, q) * (s0 * k - h) % q
print(x)