#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import shelve

name = ""

end = 10
enemies = [3, 5, 7, 9]

def handle_move(new_loc, db):
    if new_loc < 0 or new_loc > end:
        print("You can't go this way anymore")
        return
    db[f"{name}_location"] = new_loc
    if new_loc == end:
        print("You have reached the end and find a flag!")
        db[f"{name}_hasFlag"] = 1
        return
    if new_loc in enemies:
        if db[f"{name}_hasFlag"]:
            print("No! you were caught by a flag thief and the flag was token away, archive reset")
            db[f"{name}_location"] = 0
            db[f"{name}_hasFlag"] = 0
        else:
            print("Unfortunately, you were discovered by a flag thief!")
            print("Fortunately, you don't have a flag yet, they let you go")
        return
    if new_loc == 0 and db[f"{name}_hasFlag"]:
        print("You decipher the flag, well done!")
        print(*open("flag.txt"))
        db[f"{name}_location"] = 0
        db[f"{name}_hasFlag"] = 0
        exit()

def draw_map(position):
    default = """
    +------+------+------+------+------+------+------+------+------+------+------+
    |  STA |      |      |  !!  |      |  !!  |      |  !!  |      |  !!  |  FL  |
    |  RT  |      |      |  !!  |      |  !!  |      |  !!  |      |  !!  |  AG  |
    +------+------+------+------+------+------+------+------+------+------+------+"""
    default_arrow = """
       ^
      /+\\
       |
       |
   your position
    """
    padded_arrow = ""
    for line in default_arrow.split("\n"):
        padded_line = " " * 7 * position + line
        padded_arrow += padded_line + "\n"
    print(default, end = '')
    print(padded_arrow)

def menu():
    with shelve.open("db") as db:
        print()
        draw_map(db[f"{name}_location"])
        if db[f"{name}_hasFlag"]:
            print("You now have a flag, go back to the starting point and decipher it!")
        else:
            print("You don't have a flag yet, let's continue exploring")
        print("What do you want to do next?")
        print("1) Take a step forward")
        print("2) Take a step back")
        print("3) save and exit")
        print("4) view the hint")
        print("5) reset your archive")
        choice = input("\n>>> ")
        if '1' in choice:
            handle_move(db[f"{name}_location"] + 1, db)
        elif '2' in choice:
            handle_move(db[f"{name}_location"] - 1, db)
        elif '3' in choice:
            print(f"Thanks for playing, {name}！")
            exit()
        elif '4' in choice:
            if(db[f"{name}_hasFlag"]):
                print(*open("hint.txt"))
            else:
                print("To view the hint, Please go to the end to get the flag first!")
        elif '5' in choice:
            db[f"{name}_hasFlag"] = 0
            handle_move(0, db)
        else:
            print("Invalid input!")

def main():
    global name
    name = input("Young man, what is your name? ")
    with shelve.open("db") as db:
        if f"{name}_location" not in db or f"{name}_hasFlag" not in db:
            db[f"{name}_location"] = 0
            db[f"{name}_hasFlag"] = 0
            print(f"Creating an archive for you...")
        else:
            print(f"Detected that {name} already have an archive, reading your progress...")
    print(f"Welcome to the Adventures of the Brave, {name}!")
    print("Follow this road to get the flag back!")
    print("But be careful not to be caught by flag thieves")
    while(1):
        menu()

if __name__ == '__main__':
    main()