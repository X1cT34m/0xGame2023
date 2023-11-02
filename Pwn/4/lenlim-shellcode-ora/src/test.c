#include<stdio.h>
#include<sys/mman.h>
#include<fcntl.h>
#include<errno.h>

int main() {
    int fd=open("/flag",0,0);
    void *p = mmap(0x13370000,0x1000,PROT_READ,,fd,0);
    if (p==MAP_FAILED) {
        printf("mmap failed, error: %d\n",errno);
        return 1;
    }
    printf("%s\n",p);
    return 0;
}