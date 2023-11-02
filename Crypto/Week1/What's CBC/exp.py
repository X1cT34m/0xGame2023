from Crypto.Util.number import *

def bytes_xor(a,b):
	a,b=bytes_to_long(a),bytes_to_long(b)
	return long_to_bytes(a^b)

def decrypt(text,key):
	result = b''
	for i in text:
		result += ((i^key)).to_bytes(1,'big')
	return result

def CBCinv(enc,iv,key):
	result = b''
	block=[enc[_*8:(_+1)*8] for _ in range(len(enc)//8)]
	for i in block:
		temp = decrypt(i,key)
		tmp = bytes_xor(iv,temp)
		iv = i
		result += tmp
	return result

iv = b'11111111'
enc = b"\x8e\xc6\xf9\xdf\xd3\xdb\xc5\x8e8q\x10f>7.5\x81\xcc\xae\x8d\x82\x8f\x92\xd9o'D6h8.d\xd6\x9a\xfc\xdb\xd3\xd1\x97\x96Q\x1d{\\TV\x10\x11"
for key in range(0xff):
	dec = (CBCinv(enc,iv,key))
	if b'0xGame' in dec:
		print(dec)