// gcc ret2text.c -o ret2text -fno-stack-protector -no-pie -z lazy
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<unistd.h>
#include<sys/mman.h>
int set_rax(int val) {
    return val;
}
void gadget() {
    __asm__ (
        "syscall;"
        "ret;"
    );
}
void bufinit() {
    setvbuf(stdin,0,2,0);
    setvbuf(stdout,0,2,0);
    setvbuf(stderr,0,2,0);
    alarm(30);
}
int main() {
    bufinit();
    char bof_space[0x10];
    puts("I leave something interesting in this program.");
    puts("Now try to find them out!");
    puts("Input: ");
    gets(bof_space);
    return 0;
}