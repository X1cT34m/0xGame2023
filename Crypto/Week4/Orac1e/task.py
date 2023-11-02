from Crypto.Util.number import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import *
from Serve import *
from secret import flag
import random

def pad(text):
    tmp = len(text)%16
    pad_num = 16 - tmp
    text += (pad_num)*bytes([pad_num])
    return text

def unpad(text):
    num = int(text[-1])
    if num == 0:return b'False'
    for i in range(1,num+1):
        if int(text[-i]) != num:
            return b'False'
    else:
        tmp = text[:-num]
        return b'Data update'

def encrypt(plain_text, key):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text))
    return iv + cipher_text

def decrypt(cipher_text, key):
    iv = cipher_text[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    tmp = cipher.decrypt(cipher_text[AES.block_size:])
    result = unpad(tmp)
    return result
    
iv = get_random_bytes(AES.block_size)
key = get_random_bytes(16)

class test(Task):
    def handle(self):
        if not self.proof_of_work():
            self.send(b'[!] Wrong!')
            return
        signal.signal(signal.SIGALRM, self.timeout_handler)
        signal.alarm(300)
        enc = encrypt(flag,key)
        self.send(b'Here are the secret:')
        self.send(b64encode(enc))
        self.send(b'May be you can send something to decrypt it?')
        while True:
            data = self.recv()
            try:
                self.send(decrypt(b64decode(data),key))
            except:
                self.send(b'invaild input')

if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 10002
    server = ForkedServer((HOST, PORT), test)
    server.allow_reuse_address = True
    print(HOST, PORT)
    server.serve_forever()