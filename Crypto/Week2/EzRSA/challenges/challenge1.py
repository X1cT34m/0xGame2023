from Crypto.Util.number import *
import random

class RSAServe:
    def __init__(self) -> None:
        self.e = 65537
        self.p = getPrime(1024)
        self.q = getPrime(1024)
        self.n = self.q*self.p
        self.g, self.r1 = [random.randint(1, self.q*self.p) for _ in range(2)]
        self.gift = pow(self.g, self.r1 * (self.p - 1), self.n)
        self.m = b"Fermat's little theorem"

    def encrypt(self):
        m_ = bytes_to_long(self.m)
        c = pow(m_, self.e, self.p*self.q)
        return hex(c)

    def check(self, msg):
        return msg == self.m

    def pubkey(self):
        return self.p*self.q, self.e,self.gift
