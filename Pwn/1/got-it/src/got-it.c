// gcc got-it.c -o got-it -fno-stack-protector -z lazy -no-pie
#include<stdio.h>
#include<stdlib.h>
char list[0x10][8];
void bufinit() {
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
    alarm(30);
}
void menu() {
    puts("1. Add a student");
    puts("2. Show a student");
    puts("3. Edit a student");
    puts("4. Exit system");
    printf(">> ");
}
void add() {
    int idx;
    printf("Input student id: ");
    scanf("%d", &idx);
    if (idx>=0x10) {
        puts("Invalid id!");
        return;
    }
    printf("Input student name: ");
    read(0, list[idx], 8);
}
void show() {
    int idx;
    printf("Input student id: ");
    scanf("%d", &idx);
    if (idx>=0x10) {
        puts("Invalid id!");
        return;
    }
    printf("Student name: %s\n", list[idx]);
}
void edit() {
    int idx;
    printf("Input student id: ");
    scanf("%d", &idx);
    if (idx>=0x10) {
        puts("Invalid id!");
        return;
    }
    printf("Input new student name: ");
    read(0, list[idx], 8);
}
void trick() {
    exit("/bin/sh");
}
int main() {
    bufinit();
    while (1) {
        int ch;
        menu();
        scanf("%d", &ch);
        switch (ch)
        {
        case 1:
            add();
            break;
        case 2:
            show();
            break;
        case 3:
            edit();
            break;
        case 4:
            puts("Thanks for using!");
            exit(0);
        case 0x2023:
            trick();
            break;
        default:
            break;
        }
    }

}