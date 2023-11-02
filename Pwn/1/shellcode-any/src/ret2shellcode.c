//gcc ret2shellcode.c -o ret2shellcode -fno-stack-protector -no-pie -z lazy
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<sys/mman.h>
void bufinit() {
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
    alarm(60);
}
int main() {
    bufinit();
    char *shellcode_space=mmap(0x20230000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    puts("Now show me your code:");
    read(0, shellcode_space, 0x100);
    puts("Implementing security mechanism...");
    srand(time(0));
    shellcode_space+=rand()%0x100;
    close(1);
    puts("Done!");
    ((void(*)())shellcode_space)();
    return 0;
}