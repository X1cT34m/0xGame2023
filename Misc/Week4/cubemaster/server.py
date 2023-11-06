import numpy as np
import copy as cp
from sty import *
import random
import signal

faces = [np.zeros((3, 3))]

for i in range(1, 6):
    faces.append(np.ones((3, 3)) + faces[i - 1])

t = np.array([[0, 0, 1],
              [0, 1, 0],
              [1, 0, 0]])

def init(faces):
    faces = [np.zeros((3, 3))]

    for i in range(1, 6):
        faces.append(np.ones((3, 3)) + faces[i - 1])

def clockwise(face):
    face = face.transpose().dot(t)
    return face

def antiClockwise(face):
    face = face.dot(t).transpose()
    return face

def U(FACES):
    FACES[0] = clockwise(FACES[0])
    FACES_new = cp.deepcopy(FACES)
    a, b, c, d = FACES_new[4], FACES_new[2], FACES_new[5], FACES_new[3]
    FACES[4][0], FACES[2][0], FACES[5][0], FACES[3][0] = d[0], a[0], b[0], c[0]

def _U(FACES):
    FACES[0] = antiClockwise(FACES[0])
    FACES_new = cp.deepcopy(FACES)
    a, b, c, d = FACES_new[4], FACES_new[2], FACES_new[5], FACES_new[3]
    FACES[4][0], FACES[2][0], FACES[5][0], FACES[3][0] = b[0], c[0], d[0], a[0]

def D(FACES):
    FACES[1] = clockwise(FACES[1])
    FACES_new = cp.deepcopy(FACES)
    a, b, c, d = FACES_new[4], FACES_new[2], FACES_new[5], FACES_new[3]
    FACES[4][2], FACES[2][2], FACES[5][2], FACES[3][2] = b[2], c[2], d[2], a[2]

def _D(FACES):
    FACES[1] = antiClockwise(FACES[1])
    FACES_new = cp.deepcopy(FACES)
    a, b, c, d = FACES_new[4], FACES_new[2], FACES_new[5], FACES_new[3]
    FACES[4][2], FACES[2][2], FACES[5][2], FACES[3][2] = d[2], a[2], b[2], c[2]

def L(FACES):
    FACES[2] = clockwise(FACES[2])
    FACES_new = cp.deepcopy(FACES)
    a, b, c, d = clockwise(FACES_new[4]), clockwise(FACES_new[1]), antiClockwise(FACES_new[5]), clockwise(FACES_new[0])
    e, f, g, h = cp.deepcopy(a), cp.deepcopy(b), cp.deepcopy(c), cp.deepcopy(d)
    e[0], f[0], g[0], h[0] = d[0], a[0], b[0], c[0]
    FACES[4], FACES[1], FACES[5], FACES[0] = antiClockwise(e), antiClockwise(f), clockwise(g), antiClockwise(h)

def _L(FACES):
    FACES[2] = antiClockwise(FACES[2])
    FACES_new = cp.deepcopy(FACES)
    a, b, c, d = clockwise(FACES_new[4]), clockwise(FACES_new[1]), antiClockwise(FACES_new[5]), clockwise(FACES_new[0])
    e, f, g, h = cp.deepcopy(a), cp.deepcopy(b), cp.deepcopy(c), cp.deepcopy(d)
    e[0], f[0], g[0], h[0] = b[0], c[0], d[0], a[0]
    FACES[4], FACES[1], FACES[5], FACES[0] = antiClockwise(e), antiClockwise(f), clockwise(g), antiClockwise(h)

def R(FACES):
    FACES[3] = clockwise(FACES[3])
    FACES_new = cp.deepcopy(FACES)
    a, b, c, d = antiClockwise(FACES_new[4]), antiClockwise(FACES_new[1]), clockwise(FACES_new[5]), antiClockwise(FACES_new[0])
    e, f, g, h = cp.deepcopy(a), cp.deepcopy(b), cp.deepcopy(c), cp.deepcopy(d)
    g[0], f[0], e[0], h[0] = d[0], c[0], b[0], a[0]
    FACES[4], FACES[1], FACES[5], FACES[0] = clockwise(e), clockwise(f), antiClockwise(g), clockwise(h)

def _R(FACES):
    FACES[3] = antiClockwise(FACES[3])
    FACES_new = cp.deepcopy(FACES)
    a, b, c, d = antiClockwise(FACES_new[4]), antiClockwise(FACES_new[1]), clockwise(FACES_new[5]), antiClockwise(FACES_new[0])
    e, f, g, h = cp.deepcopy(a), cp.deepcopy(b), cp.deepcopy(c), cp.deepcopy(d)
    f[0], g[0], h[0], e[0] = a[0], b[0], c[0], d[0]
    FACES[4], FACES[1], FACES[5], FACES[0] = clockwise(e), clockwise(f), antiClockwise(g), clockwise(h)

def F(FACES):
    FACES[4] = clockwise(FACES[4])
    FACES_new = cp.deepcopy(FACES)
    a, b, c, d = clockwise(clockwise(FACES_new[0])), FACES_new[1], antiClockwise(FACES_new[2]), clockwise(FACES_new[3])
    e, f, g, h = cp.deepcopy(a), cp.deepcopy(b), cp.deepcopy(c), cp.deepcopy(d)
    e[0], g[0], f[0], h[0] = c[0], b[0], d[0], a[0]
    FACES[0], FACES[1], FACES[2], FACES[3] = clockwise(clockwise(e)), f, clockwise(g), antiClockwise(h)

def _F(FACES):
    FACES[4] = antiClockwise(FACES[4])
    FACES_new = cp.deepcopy(FACES)
    a, b, c, d = clockwise(clockwise(FACES_new[0])), FACES_new[1], antiClockwise(FACES_new[2]), clockwise(FACES_new[3])
    e, f, g, h = cp.deepcopy(a), cp.deepcopy(b), cp.deepcopy(c), cp.deepcopy(d)
    g[0], f[0], h[0], e[0] = a[0], c[0], b[0], d[0]
    FACES[0], FACES[1], FACES[2], FACES[3] = clockwise(clockwise(e)), f, clockwise(g), antiClockwise(h)

def B(FACES):
    FACES[5] = clockwise(FACES[5])
    FACES_new = cp.deepcopy(FACES)
    a, b, c, d = FACES_new[0], clockwise(clockwise(FACES_new[1])), clockwise(FACES_new[2]), antiClockwise(FACES_new[3])
    e, f, g, h = cp.deepcopy(a), cp.deepcopy(b), cp.deepcopy(c), cp.deepcopy(d)
    g[0], f[0], h[0], e[0] = a[0], c[0], b[0], d[0]
    FACES[0], FACES[1], FACES[2], FACES[3] = e, clockwise(clockwise(f)), antiClockwise(g), clockwise(h)

def _B(FACES):
    FACES[5] = antiClockwise(FACES[5])
    FACES_new = cp.deepcopy(FACES)
    a, b, c, d = FACES_new[0], clockwise(clockwise(FACES_new[1])), clockwise(FACES_new[2]), antiClockwise(FACES_new[3])
    e, f, g, h = cp.deepcopy(a), cp.deepcopy(b), cp.deepcopy(c), cp.deepcopy(d)
    e[0], g[0], f[0], h[0] = c[0], b[0], d[0], a[0]
    FACES[0], FACES[1], FACES[2], FACES[3] = e, clockwise(clockwise(f)), antiClockwise(g), clockwise(h)

def E(FACES):#中层1
    FACES_new = cp.deepcopy(FACES)
    a, b, c, d = FACES_new[4], FACES_new[2], FACES_new[5], FACES_new[3]
    FACES[4][1], FACES[2][1], FACES[5][1], FACES[3][1] = b[1], c[1], d[1], a[1]

def _E(FACES):#中层1逆
    FACES_new = cp.deepcopy(FACES)
    a, b, c, d = FACES_new[4], FACES_new[2], FACES_new[5], FACES_new[3]
    FACES[4][1], FACES[2][1], FACES[5][1], FACES[3][1] = d[1], a[1], b[1], c[1]

def M(FACES):#中层2
    FACES_new = cp.deepcopy(FACES)
    a, b, c, d = clockwise(FACES_new[4])[1], clockwise(FACES_new[0])[1], antiClockwise(FACES_new[5])[1], clockwise(FACES_new[1])[1]
    FACES_new[4], FACES_new[0], FACES_new[5], FACES_new[1] = clockwise(FACES_new[4]), clockwise(FACES_new[0]), antiClockwise(FACES_new[5]), clockwise(FACES_new[1])
    FACES_new[4][1], FACES_new[0][1], FACES_new[5][1], FACES_new[1][1] = b, c, d, a
    FACES[4], FACES[0], FACES[5], FACES[1] = antiClockwise(FACES_new[4]), antiClockwise(FACES_new[0]), clockwise(FACES_new[5]), antiClockwise(FACES_new[1])

def _M(FACES):#中层2逆
    FACES_new = cp.deepcopy(FACES)
    a, b, c, d = clockwise(FACES_new[4])[1], clockwise(FACES_new[0])[1], antiClockwise(FACES_new[5])[1], clockwise(FACES_new[1])[1]
    FACES_new[4], FACES_new[0], FACES_new[5], FACES_new[1] = clockwise(FACES_new[4]), clockwise(FACES_new[0]), antiClockwise(FACES_new[5]), clockwise(FACES_new[1])
    FACES_new[4][1], FACES_new[0][1], FACES_new[5][1], FACES_new[1][1] = d, a, b, c
    FACES[4], FACES[0], FACES[5], FACES[1] = antiClockwise(FACES_new[4]), antiClockwise(FACES_new[0]), clockwise(FACES_new[5]), antiClockwise(FACES_new[1])

def S(FACES):#中层3
    FACES_new = cp.deepcopy(FACES)
    a, b, c, d = FACES_new[0], clockwise(clockwise(FACES_new[1])), clockwise(FACES_new[2]), antiClockwise(FACES_new[3])
    e, f, g, h = cp.deepcopy(a), cp.deepcopy(b), cp.deepcopy(c), cp.deepcopy(d)
    g[1], f[1], h[1], e[1] = b[1], d[1], a[1], c[1]
    FACES[0], FACES[1], FACES[2], FACES[3] = e, clockwise(clockwise(f)), antiClockwise(g), clockwise(h)

def _S(FACES):#中层3逆
    FACES_new = cp.deepcopy(FACES)
    a, b, c, d = FACES_new[0], clockwise(clockwise(FACES_new[1])), clockwise(FACES_new[2]), antiClockwise(FACES_new[3])
    e, f, g, h = cp.deepcopy(a), cp.deepcopy(b), cp.deepcopy(c), cp.deepcopy(d)
    g[1], f[1], h[1], e[1] = a[1], c[1], b[1], d[1]
    FACES[0], FACES[1], FACES[2], FACES[3] = e, clockwise(clockwise(f)), antiClockwise(g), clockwise(h)

def X(FACES):#整体x
    FACES_new = cp.deepcopy(FACES)
    FACES[0], FACES[1], FACES[2], FACES[3], FACES[4], FACES[5] = FACES_new[4], clockwise(clockwise(FACES_new[5])), antiClockwise(FACES_new[2]), clockwise(FACES_new[3]), FACES_new[1], clockwise(clockwise(FACES_new[0]))

def Y(FACES):#整体y
    FACES_new = cp.deepcopy(FACES)
    FACES[0], FACES[1], FACES[2], FACES[3], FACES[4], FACES[5] = clockwise(FACES_new[0]), antiClockwise(FACES_new[1]), FACES_new[4], FACES_new[5], FACES_new[3], FACES_new[2]

def Z(FACES):#整体z
    FACES_new = cp.deepcopy(FACES)
    FACES[0], FACES[1], FACES[2], FACES[3], FACES[4], FACES[5] = clockwise(FACES_new[2]), clockwise(FACES_new[3]), clockwise(FACES_new[1]), clockwise(FACES_new[0]), clockwise(FACES_new[4]), antiClockwise(FACES_new[5])

def coloroutput(number):
    fg.white = Style(RgbFg(255, 255, 255))
    fg.yellow = Style(RgbFg(255, 255, 0))
    fg.blue = Style(RgbFg(0, 0, 255))
    fg.red = Style(RgbFg(255, 0, 0))
    fg.orange = Style(RgbFg(255, 150, 50))
    fg.green = Style(RgbFg(0, 255, 0))
    if(number == 0):
        return fg.yellow + u"\u25A0" + fg.rs
    elif(number == 1):
        return fg.white + u"\u25A0" + fg.rs
    elif(number == 2):
        return fg.green + u"\u25A0" + fg.rs
    elif(number == 3):
        return fg.blue + u"\u25A0" + fg.rs
    elif(number == 4):
        return fg.red + u"\u25A0" + fg.rs
    elif(number == 5):
        return fg.orange + u"\u25A0" + fg.rs

def show(FACES):
    print()
    for i in range(3):
        print("     ", coloroutput(FACES[0][i][0]), coloroutput(FACES[0][i][1]), coloroutput(FACES[0][i][2]))
    for i in range(3):
        print(coloroutput(FACES[2][i][0]), coloroutput(FACES[2][i][1]), coloroutput(FACES[2][i][2]), end=" ")
        print(coloroutput(FACES[4][i][0]), coloroutput(FACES[4][i][1]), coloroutput(FACES[4][i][2]), end=" ")
        print(coloroutput(FACES[3][i][0]), coloroutput(FACES[3][i][1]), coloroutput(FACES[3][i][2]), end=" ")
        print(coloroutput(FACES[5][i][0]), coloroutput(FACES[5][i][1]), coloroutput(FACES[5][i][2]))
    for i in range(3):
        print("     ", coloroutput(FACES[1][i][0]), coloroutput(FACES[1][i][1]), coloroutput(FACES[1][i][2]))
    print()

def moves(faces, lst):
    for x in lst:
        if x == 'U':
            U(faces)
        elif x == 'u':
            _U(faces)
        elif x == 'D':
            D(faces)
        elif x == 'd':
            _D(faces)
        elif x == 'L':
            L(faces)
        elif x == 'l':
            _L(faces)
        elif x == 'R':
            R(faces)
        elif x == 'r':
            _R(faces)
        elif x == 'F':
            F(faces)
        elif x == 'f':
            _F(faces)
        elif x == 'B':
            B(faces)
        elif x == 'b':
            _B(faces)
        elif x == 'E':
            E(faces)
        elif x == 'e':
            _E(faces)
        elif x == 'M':
            M(faces)
        elif x == 'm':
            _M(faces)
        elif x == 'S':
            S(faces)
        elif x == 's':
            _S(faces)
        elif x == 'X':
            X(faces)
        elif x == 'Y':
            Y(faces)
        elif x == 'Z':
            Z(faces)
        else :
            print("Invalid Input")
            return 0

def disruption(faces):
    table = "UuDdLlRrFfBbEeMmSs"
    choose = ""
    for i in range(200):
        choose += table[random.randint(0,17)]
    moves(faces, choose)

def check(faces):
    for face in faces:
        rows_equal = np.all(face == face[0, :], axis=1)
        cols_equal = np.all(face == face[:, 0], axis=0)
        all_equal = np.all(rows_equal) and np.all(cols_equal)
        if(not all_equal):
            return False
    return True

def main(gift):
    print()
    print("Please make your choice")
    print("(1) show the cube")
    print("(2) move")
    print("(3) check")
    print("(4) some information")
    print("(0) exit")
    a = input("your choice: ").strip()
    if(a == "1"):
        show(faces)
    elif(a == "2"):
        lst = input("your step:")
        moves(faces, lst)
        print("after move:")
        show(faces)
    elif(a == "3"):
        res = check(faces)
        if(res):
            print("Congratulations!")
            print()
            print(gift)
            return 1
        else:
            print("The magic cube has not been restored yet!")
    elif(a == "4"):
        info = """
        If you don't know how to play magic cube, you can check this link first
        https://zhuanlan.zhihu.com/p/34469422
        The part1, part2, and part4 are implemented here
        The commands that can be used in this question are as follows:
        UuDdLlRrFfBbEeMmSsXYZ
        Upper case is clockwise, lower case is nticlockwise
        and the provided data is a cube expansion diagram of the magic cube
        """
        print(info)
    elif(a == "0"):
        print("Bye~")
        exit()
    else:
        print("Invalid input")

def baby():
    print("after disruption:")
    disruption(faces)
    show(faces)
    while True:
        res = main("aHR0cHM6Ly93d3cuYmlsaWJpbGkuY29tL3ZpZGVvL0JWMUdKNDExeDdoNw==")
        if(res):
            exit()

def worldrecord():
    signal.alarm(3)
    print("after disruption:")
    disruption(faces)
    show(faces)
    while True:
        res = main("md5(flag) == 6dba5f8b93e25ca48f897a75bcdf1588")
        if(res):
            exit()

def insane():
    print("after disruption:")
    disruption(faces)
    show(faces)
    flag = open("flag.txt").read()
    score = 0
    while True:
        signal.alarm(3)
        res = main("your score: " + str(score + 1))
        signal.alarm(0)
        if(res):
            score += 1
            init(faces)
        else:
            continue
        if(score >= 50):
            print("Give you flag:")
            print()
            print(flag)
            exit()
        print("after disruption:")
        disruption(faces)
        show(faces)

def menu():
    banner = """
    ┏┓  ┓     ┳┳┓        
    ┃ ┓┏┣┓┏┓  ┃┃┃┏┓┏╋┏┓┏┓
    ┗┛┗┻┗┛┗   ┛ ┗┗┻┛┗┗ ┛ 
                        
    """
    print(banner)
    print("Just try to restore this third order magic cube!")
    print()
    print("origin:")
    show(faces)
    print("Choose the difficulty you want to challenge")
    print()
    print("(1) baby")
    print("(2) world record")
    print("(3) insane")
    b = input("your choice: ").strip()
    if(b == '1'):
        baby()
    elif(b == '2'):
        worldrecord()
    elif(b == '3'):
        insane()
    else:
        print("Invalid input")
    

try:
    menu()
except KeyboardInterrupt:
    print()
    print()
    print("Why you press Ctrl+C!!!")
    exit()