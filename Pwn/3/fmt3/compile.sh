#!/bin/bash
SRC_NAME="fmt3.c"
BIN_NAME="fmt3"

gcc src/$SRC_NAME -o build/$BIN_NAME
gcc src/$SRC_NAME -o dist/$BIN_NAME
git add . && git commit -m "attach update" && git push
