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
void bufinit() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
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
int gadget() {
    __asm__ (
        "syscall;"
        "ret;"
        "push 15;"
        "pop rax;"
        "ret;"
    );
}

int main() {
    bufinit();
    sandbox();
    char buf[8];
    syscall(0, 0, buf, 0x900);
}
