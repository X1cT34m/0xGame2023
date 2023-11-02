//gcc str0terminate.c -o str_basic
// I wrote a little bot.
// You can tell it your name and email,
// and it will say hello, then send a welcome email to you.
// But the email function is protect with a random password......
// Anyway, now try to say hello to him!
// If you don't know what to do......
// Just try, then you will definitely get something interesting.

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
char flag[0x50];
char name[0x20];
int seed;
char pass[0x20];
void bufinit() {
    setvbuf(stdin,0,2,0);
    setvbuf(stdout,0,2,0);
    setvbuf(stderr,0,2,0);
    alarm(30);
}
void init_flag() {
    int rand_fd=open("/dev/urandom",0);
    if (rand_fd < 0) {
        perror("rand error");
        exit(0);
    }
    read(rand_fd,&seed,4);
    close(rand_fd);
    srand(seed);

    int flag_fd;
    char buf[0x100];
    flag_fd = open("flag",0);
    if(flag_fd < 0) {
        perror("flag error");
        exit(0);
    }
    read(flag_fd,flag,0x100);
    close(flag_fd);
}
void bot() {
    // input name
    printf("Welcome to SOC2023!.\n");
    printf("Name: ");
    read(0,name,0x20);

    // input email
    printf("Password: ");
    read(0,pass,0x20);
    
    // check
    if (strncmp(name,"admin",5)!=0 || strncmp(pass,"1s_7h1s_p9ss_7tuIy_sAf3?",25)!=0) {
        perror("Credential verification failed!\n");
        goto FINAL;
    }
    // prepare userdata
    printf("Welcome back, %s!\n",name); // leak flag1
    sleep(1);
    printf("New email from %s, title: %s","0xGame2023 admin","Env now up! Flag here!\n");
    printf("Wanna see it?");
    char ch=getchar();
    if (ch!='y' && ch!='Y') {
        goto FINAL;
    }
    sleep(1);
    printf("Warning! Security alert!\n");
    printf("Input the security code to continue: ");
    unsigned int challenge_buf,challenge,arg1,arg2;
    arg1=rand()^0xd0e0a0d0;
    arg2=rand()^0x0b0e0e0f;
    challenge=(arg1^arg2)%1000000;
    scanf("%d",&challenge_buf);
    if (challenge_buf!=challenge) {
        perror("Challenge fail! Abort!\n");
        goto FINAL;
    }
    printf("Email content: %s\n",flag);
FINAL:
    printf("See you next time!\n");
    exit(0);
}
int main() {
    bufinit();
    init_flag();
    bot();
    return 0;
}