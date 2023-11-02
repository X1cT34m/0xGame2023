#!/bin/bash
SRC_NAME="fmt2.c"
BIN_NAME="fmt2"

gcc src/$SRC_NAME -o build/$BIN_NAME -fno-stack-protector -z lazy
gcc src/$SRC_NAME -o dist/$BIN_NAME -fno-stack-protector -z lazy
git add . && git commit -m "attach update" && git push
