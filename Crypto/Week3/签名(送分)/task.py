from ElGamal import *
import socketserver
import signal
from secert import flag
pub,pri = getKey(512)

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

        self.send(b'Here are your public key:')
        self.send(str(pub).encode())
        while True:
            #sign
            self.send(b'Pz tell me what you want to sign?')
            message = self.recv()
            if message == b'0xGame':
                self.send(b"Permission denied!")
                quit()
            self.send(b'Here are your sign:')
            r,s = sign(message,pub,pri)
            self.send(f'r={r}\ns={s}'.encode())
            #ver
            self.send(b'Tell me your signature,if you want to get the flag.')
            r = int(self.recv())
            s = int(self.recv())

            if verity(b'0xGame',(r,s),pub):
                self.send(b'Here you are:'+flag)
                self.send(b'bye~')
                quit()
                
            else:
                self.send(b"sorry~you can't get it.")

class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

class ForkedServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass

if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 10007
    server = ForkedServer((HOST, PORT), Task)
    server.allow_reuse_address = True
    print(HOST, PORT)
    server.serve_forever()