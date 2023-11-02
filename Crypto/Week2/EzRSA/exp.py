from Crypto.Util.number import *
import gmpy2
#数据从服务器上面拖下来解就好，这里就只做分解，不做解密了

#challenge1
gift = 
N = 
q = GCD(gift-1,N)
p = N//q
print(f'p={p}\nq={q}')

#challenge2
N = 
a = 2
n = 2
while True:
    a = gmpy2.powmod(a, n, N)
    res = gmpy2.gcd(a-1, N)
    if res != 1 and res != N:
        q = N // res
        print("p=",res)
        print("q=",q)
        break
    n += 1

#challenge3
def transform(x,y):    #使用辗转相除将分数x/y转为连分数的形式
    res=[]
    while y:
        res.append(x//y)
        x,y=y,x%y
    return res
def continued_fraction(sub_res):
    numerator,denominator=1,0
    for i in sub_res[::-1]:   #从sublist的后面往前循环
        denominator,numerator=numerator,i*numerator+denominator
    return denominator,numerator   #得到渐进分数的分母和分子，并返回
#求解每个渐进分数
def sub_fraction(x,y):
    res=transform(x,y)
    res=list(map(continued_fraction,(res[0:i] for i in range(1,len(res)))))  #将连分数的结果逐一截取以求渐进分数
    return res
 
def wienerAttack(n1,n2):
    for (q2,q1) in sub_fraction(n1,n2):  #用一个for循环来注意试探n1/n2的连续函数的渐进分数，直到找到一个满足条件的渐进分数
        if q1==0:
            continue
        if n1%q1==0 and q1!=1:
            return (q1,q2)
    print("该方法不适用")
 
N1=
N2=
print(wienerAttack(N1,N2))