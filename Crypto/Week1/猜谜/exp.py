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

c = b'IPxYIYPYXPAn3nXX3IXA3YIAPn3xAYnYnPIIPAYYIA3nxxInXAYnIPAIxnXYYYIXIIPAXn3XYXIYAA3AXnx='
enc = dec(c)

mask = b''
kown = b'0xGame{'
for i in range(7):
	mask += (enc[i]^(kown[i]+i)).to_bytes(1,'big')
flag = b''
for i in range(len(enc)):
	flag +=((mask[i%7]^enc[i])-i).to_bytes(1,'big')
print(flag)