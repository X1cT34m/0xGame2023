//gcc ret2libc.c -o ret2libc -fno-stack-protector -no-pie -z lazy
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<unistd.h>
void bufinit() {
    setvbuf(stdin,0,2,0);
    setvbuf(stdout,0,2,0);
    setvbuf(stderr,0,2,0);
    alarm(0x3c);
}
int main() {
    bufinit();
    int len;
    char input[0x20];
    puts("There won't be shell for you!");
    //printf("How long do you want to input? (I think 32 is enough): ");
    //scanf("%d",&len);
    //if (len>0x20) {
    //    puts("No chance for you to overflow!");
    //    exit(1);
    //}
    puts("Now give me your input:");
    read(0,input,0x100);
    if (strlen(input)>0x20) {
        puts("No chance for you to overflow!");
        exit(1);
    }
    puts("See you next time!");
    return 0;
}