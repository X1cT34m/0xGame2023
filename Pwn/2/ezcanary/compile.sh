#!/bin/bash
SRC_NAME="ezcanary.c"
BIN_NAME="pwn"
gcc src/$SRC_NAME -o build/$BIN_NAME -fstack-protector-all -no-pie -z lazy -z noexecstack
gcc src/$SRC_NAME -o dist/$BIN_NAME  -fstack-protector-all -no-pie -z lazy -z noexecstack
