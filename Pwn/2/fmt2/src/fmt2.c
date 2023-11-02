#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
int a=0x1234abcd;
void bufinit() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    return;
}
int main() {
    bufinit();
    char buf[0x100];
    while (1) {
        printf("Input your content: ");
        read(0,buf,0x100);
        printf(buf);
        if (a==0xdeadbeef) {
            system("/bin/sh");
        }
    }
    return 0;
}