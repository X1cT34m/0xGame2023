#!/bin/bash
SRC_NAME="lenlim-ora.c"
BIN_NAME="pwn"

gcc src/$SRC_NAME -o build/$BIN_NAME -fno-stack-protector -no-pie -z lazy
gcc src/$SRC_NAME -o dist/$BIN_NAME -fno-stack-protector -no-pie -z lazy
git add . && git commit -m "attach update" && git push
