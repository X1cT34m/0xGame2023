#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
void bufinit() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    alarm(30);
    return;
}
int main() {
    bufinit();
    void *ptr;
    printf("Here's your gift: %p\n", &printf);
    printf("You have a chance to arbitrary read 8 bytes.\n");
    printf("Where do you want to read?");
    scanf("%p",&ptr);
    printf("Here you are: ");
    write(1,ptr,8);
    printf("\n");
    printf("Now show me your magic.\n");
    printf("Where do you want to place it?");
    scanf("%p",&ptr);
    printf("Now place it.\n");
    read(0,ptr,0x30);
    printf("Good luck!");
}