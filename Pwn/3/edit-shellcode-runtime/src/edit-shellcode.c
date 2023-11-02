#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<sys/mman.h>
void bufinit() {
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
    alarm(30);
}
int main() {
    bufinit();
    char *shellcode_space=mmap(0x20230000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    puts("Input your code length:");
    int len;
    scanf("%d", &len);
    if (len<0||len>0x20) {
        puts("Too long!");
        exit(0);
    }
    puts("Now show me your code:");
    read(0, shellcode_space, len);
    for(int i=0;i<len;i++) {
        if (shellcode_space[i]==0x0f&&shellcode_space[i+1]==0x05) {
            shellcode_space[i]=0x90;
            shellcode_space[i+1]=0x90;
        }
    }
    puts("Now magic time!");
    void *ptr;
    puts("Where?");
    scanf("%p", &ptr);
    puts("What?");
    read(0,ptr,8);
    return 0;
}