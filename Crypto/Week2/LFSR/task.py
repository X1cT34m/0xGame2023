from Crypto.Util.number import *
from secret import flag,secret

assert flag == b'0xGame{'+secret+b'}'

def make_mask(m):
    tmp = str(bin(bytes_to_long(m)))[2:].zfill(128)
    return tmp

def string2bits(s):
    return [int(b) for b in s]

def bits2string(bs):
    s = [str(b) for b in bs]
    return ''.join(s)

def lfsr(state, mask):
    assert(len(state) == 128)
    assert(len(mask)  == 128)

    output = 0
    for i in range(128):
        output = output ^ (state[i] & mask[i])

    return output

if __name__ == '__main__':
    initState = [0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0]
    secret = make_mask(secret)
    mask = string2bits(secret)

    for b in secret: assert(b == '0' or b == '1')
    assert(len(secret) == 128)

    for i in range(256):
        state = initState[i:]
        output = lfsr(state, mask)
        initState += [output]

    outputState = bits2string(initState[128:])
    print('outputState =', outputState)

'''
outputState = 1101111111011101100001000011111101001000111000110100010011110111010011100110100100111001101010110110101110000011110101000110010010000011111111001111000110111001100111101110010100100001101001111110001010000100111101011011100010000000100000100000100111010110
'''
