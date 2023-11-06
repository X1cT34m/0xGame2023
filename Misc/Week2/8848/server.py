#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import pyzipper
import base64
import sys

def setzip():
    zipfile = pyzipper.AESZipFile('8848.zip', 'w', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES)
    password = "very_very_very_very_long_password_which_cannot_be_cracked_easily_and_will_never_be_known_to_anyone"
    zipfile.setpassword(password.encode())
    zipfile.write('flag.txt', 'flag.txt')
    zipfile.close()
    return None

def trydecode(password):
    with pyzipper.AESZipFile('8848.zip', 'r', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as extracted_zip:
        try:
            extracted_zip.extractall(pwd=password)
            print("Success!")
            print("The flag is: ",end='')
            with open('flag.txt', 'r') as f:
                print(f.read())
        except:
            print("Wrong password!")
            exit()

def checker(text):
    if(len(text) > 30):
        print('Too long!')
        exit()

def main():
    setzip()
    password = input("Please input the base64-encoded password to decompress the 8848.zip: ")
    checker(password)
    try:
        password = base64.b64decode(password)
    except:
        print('invalid base64 string!')
        exit()
    trydecode(password)

if __name__ == '__main__':
    main()