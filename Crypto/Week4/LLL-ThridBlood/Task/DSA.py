from Crypto.Util.number import *
from random import getrandbits,randint
from hashlib import sha1
from secret import pri_key

class DSA:
    def __init__(self):
        self.q = getPrime(160)
        while True:
            tmp = self.q*getrandbits(864)
            if isPrime(tmp+1):
                self.p = tmp+1
                break
        self.x = pri_key
        assert self.p%self.q == 1
        h = randint(1,self.p-1)
        self.g = pow(h,(self.p-1)//self.q,self.p)
        self.y = pow(self.g,self.x,self.p)

    def sign(self,m):
        H = bytes_to_long(sha1(m).digest())
        k = getrandbits(128)
        r = pow(self.g,k,self.p)%self.q
        s = (inverse(k,self.q)*(H+r*self.x))%self.q
        return (s,r)

    def verify(self,m,s_,r_):
        H = bytes_to_long(sha1(m).digest())
        u1 = (inverse(s_,self.q)*H)%self.q
        u2 = (inverse(s_,self.q)*r_)%self.q
        r = (pow(self.g,u1,self.p)*pow(self.y,u2,self.p))%self.p%self.q
        if r == r_:
            return True
        else:
            return False
