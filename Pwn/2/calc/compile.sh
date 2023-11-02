#!/bin/bash
SRC_NAME="calc.c"
BIN_NAME="pwn"
gcc src/$SRC_NAME -o build/$BIN_NAME
gcc src/$SRC_NAME -o dist/$BIN_NAME

