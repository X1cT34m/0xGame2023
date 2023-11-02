from Crypto.Util.number import *
from secret import flag,key

def bytes_xor(a,b):
	a,b=bytes_to_long(a),bytes_to_long(b)
	return long_to_bytes(a^b)

def pad(text):
	if len(text)%8:
		pad = 8-(len(text)%8)
		text += pad.to_bytes(1,'big')*pad
		return text
	else:
		return text

def Encrypt_CBC(text,iv,key):
	result = b''
	text = pad(text)
	block=[text[_*8:(_+1)*8] for _ in range(len(text)//8)]
	for i in block:
		tmp = bytes_xor(iv,i)
		iv = encrypt(tmp,key)
		result += iv
	return result

def encrypt(text,key):
	result = b''
	for i in text:
		result += ((i^key)).to_bytes(1,'big')
	return result

iv = b'11111111'
enc = (Encrypt_CBC(flag,iv,key))
print(f'enc = {enc}')

#enc = b"\x8e\xc6\xf9\xdf\xd3\xdb\xc5\x8e8q\x10f>7.5\x81\xcc\xae\x8d\x82\x8f\x92\xd9o'D6h8.d\xd6\x9a\xfc\xdb\xd3\xd1\x97\x96Q\x1d{\\TV\x10\x11"