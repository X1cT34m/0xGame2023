// gcc ret2text.c -o ret2text -fno-stack-protector -no-pie -z lazy
// just ret2text and gadgets
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
void bufinit() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    alarm(0x3c);
}
int main() {
    bufinit();
    int input[0x10];
    puts("Welcome to 0xGame2023!");
    puts("Tell me sth interesting, and I will give you what you want.");
    read(0, input, 0x100);
    if (input[2]%2023==2023)
        system("/bin/sh\x00");
    else
        puts("Not that interesting. Bye.");
    return 0;
}
