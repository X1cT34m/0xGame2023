import os
import string
from hashlib import sha256
from string import ascii_uppercase
from random import shuffle,choice,randint
import socketserver
import signal
from DSA import *
from secret import flag
GAME = DSA()

MENU = """
  Welcome_to_Final_Chanllange!
/----------------------------\\
|          options           |
| [S]ign                     |
| [V]erify                   |
| [C]heck answer             |
\\---------------------------/
"""

class Task(socketserver.BaseRequestHandler):
    def proof_of_work(self):
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

    def handle(self):
        signal.signal(signal.SIGALRM, self.timeout_handler)
        signal.alarm(300)
        if not self.proof_of_work():
            self.send(b'[!] Wrong!')
            return
        self.send(MENU.encode())
        self.send(b'Here are your public key:')
        self.send(f'q={GAME.q}\np={GAME.p}\ng={GAME.g}\ny={GAME.y}'.encode())
        while True:
            self.send(b'What you want to choice?')
            code = self.recv()
            
            if code == b'S':
                self.send(b'What you want to sign?')
                msg = self.recv()
                if msg == b'admin':
                    self.send(b'Permission denied!')
                    self.send(b'Are you trying hack me?No way!')
                    quit()
                self.send(b'Here are your signature:')
                s,r = GAME.sign(msg)
                self.send(f's = {s}'.encode())
                self.send(f'r = {r}'.encode())

            elif code == b'V':
                self.send(b"Let's check your signature.")
                self.send(b'Tell me your message:')
                msg = self.recv()
                self.send(b'Tell me the signature (s,r):')
                s = int(self.recv())
                r = int(self.recv())
                if GAME.verify(msg,s,r):
                    self.send(b'OK,it work')
                else:
                    self.send(b'Something wrong?')

            elif code == b'C':
                self.send(b"Tell me the signature of 'admin'")
                s = int(self.recv())
                r = int(self.recv())
                if GAME.verify(b'admin',s,r):
                    self.send(b'Congratulations!You are Master of Cryptography!')
                    self.send(b'Here are your flag:')
                    self.send(flag)
                    quit()
                else:
                    self.send(b'It seems Something wrong?')
            else:
                self.send(b'invaild input')

class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

class ForkedServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass

if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 10002
    server = ForkedServer((HOST, PORT), Task)
    server.allow_reuse_address = True
    print(HOST, PORT)
    server.serve_forever()