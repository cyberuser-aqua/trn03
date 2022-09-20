#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>

struct e
{
};
int main(void)
{
    char buf[10] = {0};
    read(STDIN_FILENO, buf, 4);
    printf("%s\n", buf);
    return 0;
}