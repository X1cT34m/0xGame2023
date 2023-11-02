#!/bin/bash
SRC_NAME="srop.c"
BIN_NAME="pwn"

gcc src/$SRC_NAME -o build/$BIN_NAME -fno-stack-protector -no-pie -z lazy -masm=intel
gcc src/$SRC_NAME -o dist/$BIN_NAME -fno-stack-protector -no-pie -z lazy -masm=intel
git add . && git commit -m "attach update" && git push
