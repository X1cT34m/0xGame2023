#include<stdio.h>
#include<stdlib.h>
char filebuf[0x200];
char filename[0x20];
void bufinit() {
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
    alarm(30);
}
int main() {
    bufinit();
    printf("Input filename to open: ");
    filename[read(0,filename,0x1f)]=0;
    printf("Input file id to read from: ");
    int fd_in;
    scanf("%d", &fd_in);
    printf("Input file id to write to: ");
    int fd_out;
    scanf("%d", &fd_out);
    close(1);
    int file_fd=open(filename, 0);
    if(file_fd==-1) {
        printf("Failed to open file!\n");
        return 0;
    }
    read(file_fd, filebuf, 0x1ff);
    write(fd_out, filebuf, 0x1ff);
    exit(0);
}