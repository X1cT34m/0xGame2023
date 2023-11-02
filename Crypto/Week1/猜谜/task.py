from secret import flag,key
from Crypto.Util.number import *

def dec(text):
	text = text.decode()
	code = 'AP3IXYxn4DmwqOlT0Q/JbKFecN8isvE6gWrto+yf7M5d2pjBuk1Hh9aCRZGUVzLS'
	unpad = 0
	tmp = ''
	if (text[-1] == '=') & (text[-2:] != '=='):
		text = text[:-1]
		unpad = -1
	if text[-2:] == '==':
		text = text[:-2]
		unpad = -2
	for i in text:
		tmp += str(bin(code.index(i)))[2:].zfill(3)
	tmp = tmp[:unpad]
	result = long_to_bytes(int(tmp,2))
	return result

def enc(text):
	code = 'AP3IXYxn4DmwqOlT0Q/JbKFecN8isvE6gWrto+yf7M5d2pjBuk1Hh9aCRZGUVzLS'
	text = ''.join([str(bin(i))[2:].zfill(8) for i in text])
	length = len(text)
	pad = b''
	if length%3 == 1:
		text += '00'
		pad = b'=='
	elif length%3 == 2:
		text += '0'
		pad = b'='
	result = [code[int(text[3*i:3*(i+1)],2)] for i in range(0,len(text)//3)]
	return ''.join(result).encode()+pad

def encrypt(flag):
	result = b''
	for i in range(len(flag)):
		result += (key[i%7]^(flag[i]+i)).to_bytes(1,'big')
	return result


c = enc(encrypt(flag))
print(f'c = {c}')

'''
c = b'IPxYIYPYXPAn3nXX3IXA3YIAPn3xAYnYnPIIPAYYIA3nxxInXAYnIPAIxnXYYYIXIIPAXn3XYXIYAA3AXnx='
'''