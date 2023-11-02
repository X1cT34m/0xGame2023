// gcc ret2text.c -o ret2text -fno-stack-protector -no-pie -z lazy
// no protection implemented
// off by null, lift up stack
// leave shellcode in stack, nop slide
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

int custom_gets_off_by_one_or_null(char *buf, int cnt) {
    for (int i=0; i<cnt; i++) {
        if (read(0, buf+i, 1)!=1) {
            puts("read error");
            exit(-1);
        }
        if (buf[i]=='\n') {
            buf[i]='\x00';
            return i;
        }
    }
    buf[cnt]='\x00';
}

void vuln() {
    puts("Try perform ROP!");
    char buf[0x100];
    custom_gets_off_by_one_or_null(buf, 0x100);
    puts("Good luck!");
    return;
}

void bufinit() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    alarm(30);
}

int main() {
    char buf[0x20];
    bufinit();
    vuln();
    return 0;
}