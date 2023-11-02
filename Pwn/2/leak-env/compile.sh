#!/bin/bash
SRC_NAME="leak-env-stack.c"
BIN_NAME="leakenv"

gcc src/$SRC_NAME -o build/$BIN_NAME
gcc src/$SRC_NAME -o dist/$BIN_NAME
git add . && git commit -m "attach update" && git push
