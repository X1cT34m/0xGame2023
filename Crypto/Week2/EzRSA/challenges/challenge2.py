from Crypto.Util.number import *
from random import choice

class RSAServe:
    def __init__(self) -> None:
        self.e = 65537
        self.m = b'EzFactor'
        self.p = self.GetMyPrime(1024)
        self.q = self.GetMyPrime(1024)

    def GetMyPrime(self,bits):
        while True:
            n = 2
            while n.bit_length() < bits:
                a = choice(sieve_base)
                n *= a
            if isPrime(n + 1):
                return n + 1

    def encrypt(self):
        m_ = bytes_to_long(self.m)
        c = pow(m_, self.e, self.p*self.q)
        return hex(c)

    def check(self, msg):
        return msg == self.m

    def pubkey(self):
        return self.p*self.q, self.e