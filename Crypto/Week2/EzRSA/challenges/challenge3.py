from Crypto.Util.number import *
from random import choice
from sympy import *
class RSAServe:
    def __init__(self) -> None:
        self.e = 65537
        self.m = b'Continued fraction'
        self.p = getPrime(896)
        self.n1 = self.getN()
        self.n2 = self.getN()

    def getN(self):
        q = getPrime(128)
        self.p = nextprime(self.p)
        return q*self.p

    def encrypt(self):
        m_ = bytes_to_long(self.m)
        c = pow(m_, self.e, self.n2)
        return hex(c)

    def check(self, msg):
        return msg == self.m

    def pubkey(self):
        return self.n1, self.n2 , self.e
