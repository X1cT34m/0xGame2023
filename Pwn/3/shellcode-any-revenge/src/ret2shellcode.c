//gcc ret2shellcode.c -o ret2shellcode -fno-stack-protector -no-pie -z lazy
#include<stdlib.h>
#include<string.h>
#include<stdio.h>
#include<fcntl.h>
#include<unistd.h>
#include<stddef.h>
#include<linux/seccomp.h>
#include<linux/filter.h>
#include<sys/prctl.h>
#include<linux/audit.h>
#include<linux/bpf.h>
#include<sys/types.h>
#include<sys/mman.h>
void bufinit() {
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
    alarm(30);
}
void sandbox() {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, arch))),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 5),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x4000000, 3, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 59, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 322, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
    };
    struct prog {
        unsigned short len;
        unsigned char *filter;
    } rule = {
        .len = sizeof(filter) >> 3,
        .filter = filter
    };
    if(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        perror("prctl(PR_SET_NO_NEW_PRIVS)");
        exit(2);
    }
    if(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &rule) < 0) {
        perror("prctl(PR_SET_SECCOMP)");
        exit(2);
    }
}
int main() {
    bufinit();
    char *shellcode_space=mmap(0x20230000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    puts("Now show me your code:");
    read(0, shellcode_space, 0x100);
    srand(time(0));
    shellcode_space+=rand()%0x100;
    puts("Implementing security mechanism...");
    sandbox();
    close(1);
    puts("Done!");
    ((void(*)())shellcode_space)();
    return 0;
}