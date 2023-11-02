#!/bin/bash
SRC_NAME="edit-shellcode.c"
BIN_NAME="pwns"

gcc src/$SRC_NAME -o build/$BIN_NAME -no-pie -z norelro -static -s
gcc src/$SRC_NAME -o dist/$BIN_NAME -no-pie -z norelro -static -s
git add . && git commit -m "attach update" && git push
