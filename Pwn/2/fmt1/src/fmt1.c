#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
void bufinit() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    alarm(30);
}
int main() {
    bufinit();
    int chg,ans;
    int *ptr=&chg;
    char buf[0x100];
    ans=0x2023;
    chg=0x20ff;
    printf("Input your content: ");
    read(0,buf,0x100);
    printf(buf);
    if(chg==ans) {
        puts("Congratulations! Now here is your shell!");
        puts("And welcome to format string world!");
        system("/bin/sh");
    }
}