//gcc ezcanary.c -o pwn -fstack-protector-all -no-pie -z lazy -z noexecstack
#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<string.h>
char binsh[]="/bin/sh";
void backdoor() {
    system("echo no backdoor!");
}
void bufinit() {
    setvbuf(stdin,0,2,0);
    setvbuf(stdout,0,2,0);
    setvbuf(stderr,0,2,0);
    alarm(30);
}

int main() {
    bufinit();
    char buf[0x10];
    puts("Ur name plz?");
    read(0, buf, 0x100);
    printf("Hello, %s. Is that right?", buf);
    char ch=getchar();
    if (ch=='y'||ch=='Y') {
        puts("Then new name plz.");
        read(0, buf, 0x100);
        printf("Hello, %s.", buf);
    }
    puts("Wish you a wonderful day. Bye.");
}