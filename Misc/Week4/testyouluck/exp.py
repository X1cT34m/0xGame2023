from web3 import Web3

for i in range(1,255):
    address = "0x943891A44EEA7e1c5871c4Ae13277539a1399C2BAF"[2:]
    data = '0xd694'+ address + hex(i)[2:].zfill(2)
    if(int(Web3.to_hex(Web3.keccak(hexstr=data))[-40:],16) % 50 == 30):
        print(i)