#!/bin/bash
gcc src/str0terminate.c -o build/pwn -fno-stack-protector -no-pie -z lazy
gcc src/str0terminate.c -o dist/pwn -fno-stack-protector -no-pie -z lazy
git add . && git commit -m "attach update" && git push