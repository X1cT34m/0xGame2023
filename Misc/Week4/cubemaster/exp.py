import numpy as np
import copy as cp
import re
from pwn import *
import kociemba

num_to_color = {
    '0': 'f',  # 黄色
    '1': 'b',  # 白色
    '2': 'r',  # 红色
    '3': 'd',  # 绿色
    '4': 'l',  # 橙色
    '5': 'u'  # 蓝色
}

color_to_number = {
    (255, 255, 0): '0',  # 黄色
    (255, 255, 255): '1',  # 白色
    (255, 0, 0): '2',  # 红色
    (0, 255, 0): '3',  # 绿色
    (255, 150, 50): '4',  # 橙色
    (0, 0, 255): '5'  # 蓝色
}

def toString(FACES):
    print()
    for i in range(3):
        print("     ", int(FACES[0][i][0]), int(FACES[0][i][1]), int(FACES[0][i][2]))
    for i in range(3):
        print(int(FACES[2][i][0]), int(FACES[2][i][1]), int(FACES[2][i][2]), end=" ")
        print(int(FACES[4][i][0]), int(FACES[4][i][1]), int(FACES[4][i][2]), end=" ")
        print(int(FACES[3][i][0]), int(FACES[3][i][1]), int(FACES[3][i][2]), end=" ")
        print(int(FACES[5][i][0]), int(FACES[5][i][1]), int(FACES[5][i][2]))
    for i in range(3):
        print("     ", int(FACES[1][i][0]), int(FACES[1][i][1]), int(FACES[1][i][2]))
    print()


def SSSS(sendsolve):
    send = ''
    for i in sendsolve:
        if len(i) > 1:
            if i[-1] == "'":
                send += i[0].lower()
            if i[-1] == "2":
                send += i[0] + i[0]
        else:
            send += i[0]
    return send


def GetColor(FACES, input_string):
    # 使用正则表达式匹配颜色代码
    color_pattern = r'\x1b\[38;2;(\d+);(\d+);(\d+)m'
    matches = re.findall(color_pattern, input_string)

    # 提取颜色并映射为数字
    result = ''.join([color_to_number.get(tuple(map(int, match)), 'X') for match in matches])

    k = 0
    for i in range(3):
        FACES[0][i][0] = result[k]
        FACES[0][i][1] = result[k + 1]
        FACES[0][i][2] = result[k + 2]
        k += 3
    for i in range(3):
        for j in range(3):
            FACES[2][i][j] = result[k + j]
        k = k + 3
        for j in range(3):
            FACES[4][i][j] = result[k + j]
        k += 3
        for j in range(3):
            FACES[3][i][j] = result[k + j]
        k += 3
        for j in range(3):
            FACES[5][i][j] = result[k + j]
        k += 3

    for i in range(3):
        for j in range(3):
            FACES[1][i][j] = result[k + j]
        k += 3


faces = [np.zeros((3, 3))]

for i in range(1, 6):
    faces.append(np.ones((3, 3)) + faces[i - 1])



'''
                          |************|
                          |*U1**U2**U3*|
                          |************|
                          |*U4**U5**U6*|
                          |************|
                          |*U7**U8**U9*|
                          |************|
              ************|************|************|************|
              *L1**L2**L3*|*F1**F2**F3*|*R1**R2**R3*|*B1**B2**B3*|
              ************|************|************|************|
              *L4**L5**L6*|*F4**F5**F6*|*R4**R5**R6*|*B4**B5**B6*|
              ************|************|************|************|
              *L7**L8**L9*|*F7**F8**F9*|*R7**R8**R9*|*B7**B8**B9*|
              ************|************|************|************|
                          |************|
                          |*D1**D2**D3*|
                          |************|
                          |*D4**D5**D6*|
                          |************|
                          |*D7**D8**D9*|
                          |************|
'''


io = remote('124.220.8.243', 1337)
io.recvuntil(b'your choice:')
io.sendline(b'3')
n = 0
for q in range(50):
    n += 1
    a = io.recvuntil(b'Please')
    GetColor(faces, a.decode())

    toString(faces)
    lst = '034125'
    num1 = ''
    num2 = ''
    for k in lst:
        for i in range(3):
            for j in range(3):
                num1 += num_to_color[str(int(faces[int(k)][i][j]))]
    print()
    for k in lst:
        num2 += num_to_color[str(int(faces[int(k)][1][1]))] * 9

    sendsolve = kociemba.solve(num1.upper(), num2.upper())
    sendsolve = sendsolve.split(' ')

    sendsolve = SSSS(sendsolve)
    print(sendsolve)

    io.recvuntil(b'your choice:')
    io.sendline(b'2')
    io.recvuntil(b'your step:')
    io.sendline(sendsolve.encode())
    io.recvuntil(b'your choice:')
    io.sendline(b'3')

io.interactive()
