#!/bin/bash
SRC_NAME="nc.c"
BIN_NAME="netcat"

gcc src/$SRC_NAME -o build/$BIN_NAME -fno-stack-protector -no-pie -z lazy
git add . && git commit -m "attach update" && git push
