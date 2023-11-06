from pwn import *
import sympy

r = remote('124.220.8.243', 11451)
def solve(equation):
    equ = equation[:-4].strip()
    method = equation[-3]
    x = sympy.Symbol('x')
    if(method == 'd'):
        derivative = sympy.diff(equ, x)
        return derivative
    elif(method == 'i'):
        derivative = sympy.integrate(equ, x)
        return derivative

r.recvuntil(b'\n\n\n')
r.sendline()
for _ in range(300):
    print(_)
    equ = r.recvline().decode().split('>')[1]
    answer = solve(equ)
    r.recvuntil(b'your answer > ')
    r.sendline(str(answer))
    r.recvline()
r.interactive()