from Crypto.Util.number import getPrime,GCD,inverse,bytes_to_long
import random

def getKey(bits):
    p = getPrime(bits)
    g = getPrime(bits//2)
    d = random.randint(1,p-2)
    y = pow(g,d,p)
    public,private = (p,g,y),d
    return public,private

def sign(m,public,private):
    m = bytes_to_long(m)
    p,g,y = public
    d = private
    while True:
        k = random.randint(1,p-1)
        if GCD(k,p-1)==1:break
    r = pow(g,k,p)
    s = ((m-d*r)*inverse(k,p-1)) % (p-1)
    return (r,s)

def verity(m,sign,public):
    m = bytes_to_long(m)
    p,g,y = public
    r,s = sign
    if pow(g,m,p) == (pow(y,r,p)*pow(r,s,p)) % p:
        return True
    else:
        return False
