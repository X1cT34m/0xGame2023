from Crypto.Util.number import *
import socketserver
import signal
from secret import flag
import random
import os
import string
from hashlib import sha256
from string import ascii_uppercase
from random import shuffle,choice,randint
import os


q = getPrime(512)
p = getPrime(512)
e = 65537
n = q*p
phi = (q-1)*(p-1)
d = inverse(e,phi)

def decrypt(c,d,n,index):
    """something go wrong"""
    d_ = d^(1<<(index))
    m_ = pow(c,d_,n)
    return str(m_)

MEMU = """
    Welc0me_2_0xGame2023!
/----------------------------\\
|          options           |
| [S]ign                     |
| [F]ault injection          |
| [C]heck answer             |
\\---------------------------/
"""


class Task(socketserver.BaseRequestHandler):
    def proof_of_work(self):
        '''验证函数'''
        random.seed(os.urandom(8))
        proof = ''.join([random.choice(string.ascii_letters+string.digits) for _ in range(20)])
        _hexdigest = sha256(proof.encode()).hexdigest()
        self.send(f"[+] sha256(XXXX+{proof[4:]}) == {_hexdigest}".encode())
        x = self.recv(prompt=b'[+] Plz tell me XXXX: ')
        if len(x) != 4 or sha256(x+proof[4:].encode()).hexdigest() != _hexdigest:
            return False
        return True

    def _recvall(self):
        BUFF_SIZE = 2048
        data = b''
        while True:
            part = self.request.recv(BUFF_SIZE)
            data += part
            if len(part) < BUFF_SIZE:
                break
        return data.strip()

    def send(self, msg, newline=True):
        try:
            if newline:
                msg += b'\n'
            self.request.sendall(msg)
        except:
            pass

    def recv(self, prompt=b'> '):
        self.send(prompt, newline=False)
        return self._recvall()

    def timeout_handler(self, signum, frame):
        raise TimeoutError

        '''以上是交互部分'''
    def handle(self):
        '''题干'''
        signal.signal(signal.SIGALRM, self.timeout_handler)
        signal.alarm(300)
        self.send(MEMU)
        if not self.proof_of_work():
            self.send(b'[!] Wrong!')
            return

        self.send(MEMU.encode())
        while True:
            code = self.recv()
            if code == b'S':
                self.send(b'What you want to sign?:')
                m = bytes_to_long(self.recv())
                c = pow(m,e,n)
                self.send(f'{n}\n{e}\n{c}'.encode())
                
            elif code == b'F':
                self.send(b'Give me the Signatrue:')
                Signatrue = int(self.recv())
                self.send(b'Where you want to interfere?')
                index = int(self.recv())
                self.send(b'The decrypt text:')
                self.send(decrypt(Signatrue,d,n,index).encode())

            elif code == b'C':
                self.send(b'Give me the private key:')
                ans = int(self.recv())
                if ans == d:
                    self.send(b'Here is your flag:')
                    self.send(flag)
                    
            else:
                self.send(b'invaild input')

class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

class ForkedServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass

if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 10005
    server = ForkedServer((HOST, PORT), Task)
    server.allow_reuse_address = True
    print(HOST, PORT)
    server.serve_forever()
