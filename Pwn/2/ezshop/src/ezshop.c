//gcc ezcanary.c -o pwn -fstack-protector-all -no-pie -z lazy -z noexecstack
#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<string.h>

int money;
int price_arr[]={4,50,10000000};
int shopping_cart[3];

void bufinit() {
    setvbuf(stdin,0,2,0);
    setvbuf(stdout,0,2,0);
    setvbuf(stderr,0,2,0);
    alarm(30);
    memset(shopping_cart,0,sizeof(shopping_cart));
    money=1000;
}

void orw() {
    int fd=open("/flag",0,0);
    if (fd<0) {
        puts("open failed!");
        exit(0);
    }
    char buf[0x100];
    read(fd,buf,0x100);
    close(fd);
    write(1,buf,0x100);
    return;
}

void shop() {
    int ch;
    int cnt;
    printf("钱包里有 %d 元\n",money);
    puts("商品列表：");
    puts("1. 快乐水 ￥4/瓶");
    puts("2. 大大酥 ￥50/大包");
    puts("3. flag  ￥10000000/个");
    puts("想买点啥？");
    scanf("%d",&ch);
    if (ch<1||ch>3) {
        puts("你是来找茬的吧？");
        return;
    }
    puts("要几个？");
    scanf("%d",&cnt);
    if (cnt>10) {
        puts("你是来找茬的吧？");
        return;
    }
    if (money-price_arr[ch-1]*cnt<0) {
        puts("钱不够啊！");
        return;
    }
    money-=price_arr[ch-1]*cnt;
    ++shopping_cart[ch-1];
    return;
}

void haokangde() {
    if (shopping_cart[2]) {
        puts("你过来哦......");
        orw();
        return;
    }
    else {
        puts("你哪有好康的啊？");
        return;
    }
}

int main() {
    int ch;
    bufinit();
    puts("欢迎来到0xGame补给站！");
    while (1) {
        puts("1. 购买");
        puts("2. 看好康的");
        puts("3. 退出");
        printf(">> ");
        scanf("%d",&ch);
        switch (ch) {
            case 1:
                shop();
                break;
            case 2:
                haokangde();
                break;
            case 3:
                exit(0);
            default:
                puts("");
                puts("你是来找茬的吧？");
                break;
        }
    }
}