#!/bin/bash
SRC_NAME="ret2shellcode.c"
BIN_NAME="ret2shellcode-revenge"

gcc src/$SRC_NAME -o build/$BIN_NAME
gcc src/$SRC_NAME -o dist/$BIN_NAME
git add . && git commit -m "attach update" && git push
