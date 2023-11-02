//gcc calc.c -o pwn
#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<string.h>

unsigned int seed;

void init_seed() {
    int fd=open("/dev/urandom",0);
    if (fd==-1) {
        puts("open error");
        exit(0);
    }
    read(fd,&seed,4);
    close(fd);
    seed+=time(0);
    srand(seed);
}
void bufinit() {
    setvbuf(stdin,0,2,0);
    setvbuf(stdout,0,2,0);
    setvbuf(stderr,0,2,0);
    alarm(5);
}

int main() {
    bufinit();
    init_seed();
    int a,b;
    int ans;
    puts("Welcome to the calc game!");
    for (int i=0;i<100;i++) {
        a=rand();
        b=rand();
        printf("====Round %d====\n",i+1);
        printf("%d+%d=",a,b);
        scanf("%d",&ans);
        if (ans==a+b) {
            puts("Correct!");
        } else {
            puts("Wrong!");
            exit(0);
        }
    }
    puts("Congratulations! Here's your shell!");
    system("/bin/sh");
}