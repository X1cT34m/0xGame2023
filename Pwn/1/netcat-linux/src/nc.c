#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    alarm(30);
    system("/bin/sh");
    return 0;
}