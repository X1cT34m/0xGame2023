from challenges.challenge1 import RSAServe as challenge1
from challenges.challenge2 import RSAServe as challenge2
from challenges.challenge3 import RSAServe as challenge3
from secret import flag
import random
import os
import string
from hashlib import sha256
from string import ascii_uppercase
from random import shuffle,choice,randint
import os
import socketserver
import signal


SCORE = [0, 0, 0]
BANNER = """
 ____  ____    _    
|  _ \/ ___|  / \   
| |_) \___ \ / _ \  
|  _ < ___) / ___ \ 
|_| \_\____/_/   \_\

Here are four challenges(1, 2, 3), solve them all then you can get flag.
"""
MEMU = """
/----------------------------\\
|          options           |
| 1. get public key          |
| 2. get cipher text         |
| 3. check                   |
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

    def Serve(self, S):
        self.send(MEMU.encode())
        while True:
            option = self.recv()
            if option == b'1':
                pubkey = S.pubkey()
                for s in pubkey:
                    self.send(str(s).encode())
            elif option == b'2':
                c = S.encrypt()
                self.send(c.encode())
            elif option == b'3':
                usr_answer = self.recv(b"input your answer: ")
                return S.check(usr_answer)
            else:
                self.send(b"invaild option")

    def handle(self):
        signal.signal(signal.SIGALRM, self.timeout_handler)
        signal.alarm(300)
        if not self.proof_of_work():
            self.send(b'[!] Wrong!')
            return
        self.send(BANNER.encode())
        while True:
            self.send(f'your score {sum(SCORE)}'.encode())
            if sum(SCORE) == 3:
                self.send(f"here are flag:{flag}".encode())
                break
            self.send(b'select challange{1,2,3}')#
            code = self.recv()
            if code == b'1':
                S = challenge1()
                res = self.Serve(S)
                if res == True:
                    SCORE[0] = 1
                    self.send(b'Conguration!You are right!')
            elif code == b'2':
                S = challenge2()
                res = self.Serve(S)
                if res == True:
                    SCORE[1] = 1
                    self.send(b'Conguration!You are right!')
            elif code == b'3':
                S = challenge3()
                res = self.Serve(S)
                if res == True:
                    SCORE[2] = 1
                    self.send(b'Conguration!You are right!')
            else:
                self.send(b'invaild input')


class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


class ForkedServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass


if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 10006
    server = ForkedServer((HOST, PORT), Task)
    server.allow_reuse_address = True
    print(HOST, PORT)
    server.serve_forever()
