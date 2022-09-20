#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <ctype.h>

#ifndef UTILS
#define UTILS

void hexdump(void *mem, unsigned int len);
void write_text_fd(int fd, unsigned long offset, long nbytes, char *text);
void write_text(char *filename, unsigned long offset, long nbytes, char *text);
void read_text_fd(int fd, char *buff, unsigned long offset, long nbytes, int dohex);
void read_text(char *filename, unsigned long offset, long nbytes, int dohex);
void print_cur(char *filename);
void setup_map(u_int32_t high, u_int32_t *base);
void map(u_int32_t kaddr);

#endif
