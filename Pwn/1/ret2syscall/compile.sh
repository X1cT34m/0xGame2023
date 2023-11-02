#!/bin/bash
SRC_NAME="ret2syscall.c"
BIN_NAME="ret2syscall"

gcc src/$SRC_NAME -o build/$BIN_NAME -fno-stack-protector -no-pie -z lazy
gcc src/$SRC_NAME -o dist/$BIN_NAME -fno-stack-protector -no-pie -z lazy
git add . && git commit -m "attach update" && git push
