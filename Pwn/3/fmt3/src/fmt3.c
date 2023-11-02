#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
void bufinit() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    alarm(30);
    return;
}
int main() {
    bufinit();
    char buf[0x100],ch;
    puts("Now things become a little interesting.");
    puts("But not that interesting......");
    puts("GO! GO! GO!");
    do {
        printf("Input your content: ");
        read(0,buf,0x100);
        printf(buf);
        puts("Want more?");
        ch=getchar();
    } while (ch=='y'||ch=='Y');
    return 0;
}