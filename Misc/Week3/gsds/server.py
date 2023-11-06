#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import random
import string
import sympy

def generate_daoshu():
    x = sympy.Symbol('x')
    base = ['sin(x)', 'cos(x)', 'x**4', 'x**3', 'x**2', 'x']
    basee = random.sample(base, random.randint(1, 6))
    equation = ''
    for i in basee:
        equation += random.choice(['+', '-']) + ' ' + random.choice(['', '2*', '3*', '4*', '5*']) + i + ' '
    equation = equation[2:-1]
    derivative = sympy.diff(equation, x)
    equation = equation + ' (d)'

    return equation, derivative

def generate_jifen():
    x = sympy.Symbol('x')
    base = ['sin(x)', 'cos(x)', 'x**4', 'x**3', 'x**2', 'x']
    basee = random.sample(base, random.randint(1, 6))
    equation = ''
    for i in basee:
        equation += random.choice(['+', '-']) + ' ' + random.choice(['', '2*', '3*', '4*', '5*']) + i + ' '
    equation = equation[2:-1]
    derivative = sympy.integrate(equation, x)
    equation = equation + ' (i)'

    return equation, derivative

def game():
    score = 0
    while score < 300:
        equation, derivative = random.choice([generate_daoshu, generate_jifen])()
        print('> ', equation)
        print()
        answer = input('your answer > ').strip()
        answer = sympy.simplify(answer)
        derivative = sympy.simplify(derivative)
        if answer == derivative:
            print('correct!')
            score += 1
        else:
            print('no!')
            print()
            print('your score: ', score)
            exit()
    if(score >= 300):
        print(*open("flag.txt"))
        exit()
    return

def main():
    print('I will give you some equations, try to find their derivatives or integrals!')
    print('(d) for derivative, (i) for integral')
    print('Answering one question correctly can earn 1 point, and 300 points can earn a flag!')
    print('One wrong answer will end the game directly')
    print('Example:')
    print('5*x**4 + 5*sin(x) - 4*cos(x) - x**2 (d)  -->   20*x**3 - 2*x + 4*sin(x) + 5*cos(x)')
    print('2*cos(x) - 3*x - x**2 - x**4 - 3*sin(x) (i)  -->  -x**5/5 - x**3/3 - 3*x**2/2 + 2*sin(x) + 3*cos(x)')
    print()
    print()
    input('press enter to start')
    game()

if __name__ == '__main__':
    main()
