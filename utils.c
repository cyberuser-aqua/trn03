#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <ctype.h>

#include "utils.h"

#ifndef HEXDUMP_COLS
#define HEXDUMP_COLS 16
#endif
#define PAGE_OFFSET 0x80000000U
#define MAP_FLAGS 0b110001111110

#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#define PRINTE(err) write(2, err, strlen(err));
#define VIRT_TO_PHYS(addr) (addr - PAGE_OFFSET)

u_int32_t mhigh = 0;
u_int32_t *mbase = 0;

void hexdump(void *mem, unsigned int len)
{
    unsigned int i, j;

    for (i = 0; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++)
    {
        /* print offset */
        if (i % HEXDUMP_COLS == 0)
        {
            printf("0x%06x: ", i);
        }

        /* print hex data */
        if (i < len)
        {
            printf("%02x ", 0xFF & ((char *)mem)[i]);
        }
        else /* end of block, just aligning for ASCII dump */
        {
            printf("   ");
        }

        /* print ASCII dump */
        if (i % HEXDUMP_COLS == (HEXDUMP_COLS - 1))
        {
            for (j = i - (HEXDUMP_COLS - 1); j <= i; j++)
            {
                if (j >= len) /* end of block, not really printing */
                {
                    putchar(' ');
                }
                else if (isprint(((char *)mem)[j])) /* printable char */
                {
                    putchar(0xFF & ((char *)mem)[j]);
                }
                else /* other char */
                {
                    putchar('.');
                }
            }
            putchar('\n');
        }
    }
}

void write_text(char *filename, unsigned long offset, long nbytes, char *text)
{
    ssize_t written = 0;

    int fd = open(filename, O_WRONLY | O_CREAT);
    if (fd == -1)
    {
        PRINTE("ERR: Could not open file for writing\n");
        goto CLEANUP;
    }

    errno = 0;
    (void)lseek(fd, (off_t)offset, SEEK_SET);
    if (errno != 0)
    {
        PRINTE("Could not seek\n");
        goto CLEANUP;
    }

    // written = write(text, 1, MIN(nbytes, strlen(text)), fd);
    written = write(fd, text, nbytes);
    if (written != nbytes)
    {
        char buff[50]; // Assuming I can't use fprintf for this...
        snprintf(buff, sizeof(buff), "WARN: Only %d bytes were written of %ld\n", written, nbytes);
        PRINTE(buff);
    }

CLEANUP:
    if (fd != -1)
    {
        close(fd);
        fd = -1;
    }
}

void read_text(char *filename, unsigned long offset, long nbytes, int dohex)
{
    ssize_t read_ = 0;
    ssize_t written = 0;

    char *buff = (char *)malloc(nbytes * sizeof(char));
    if (buff == NULL)
    {
        PRINTE("ERR: Could not allocate buffer");
        goto CLEANUP;
    }

    int fd = open(filename, O_RDONLY | O_CREAT);
    if (fd == -1)
    {
        PRINTE("ERR: Could not open file for reading\n");
        goto CLEANUP;
    }

    errno = 0;
    (void)lseek(fd, (off_t)offset, SEEK_SET);
    if (errno != 0)
    {
        PRINTE("Could not seek\n");
        goto CLEANUP;
    }

    read_ = read(fd, buff, nbytes);
    if (read_ != nbytes)
    {
        char buff[50];
        snprintf(buff, sizeof(buff), "WARN: Only %d bytes were read of %ld\n", read_, nbytes);
        PRINTE(buff);
    }

    // written = write(buff, 1, read_, stdout);
    if (dohex)
    {
        hexdump(buff, (unsigned int)read_);
    }
    else
    {
        written = write(1, buff, read_);
        if (read_ != written)
        {
            char buff[73];
            snprintf(buff, sizeof(buff), "WARN: Only %d bytes were written of %d that were read\n", written, read_);
            PRINTE(buff);
        }
    }

CLEANUP:
    if (buff != NULL)
    {
        free(buff);
        buff = NULL;
    }
    if (fd != -1)
    {
        close(fd);
        fd = -1;
    }
}

void print_cur(char *filename)
{
    int fd = open(filename, O_RDWR);
    printf("%x\n", ioctl(fd, 0x1337));
    close(fd);
}

void setup_map(u_int32_t high, u_int32_t *base)
{
    mhigh = high;
    mbase = base;
}

void map(u_int32_t kaddr)
{
    size_t i;
    // printf("%x, %x, %x, %x", kaddr, kaddr & 0xfffff000, VIRT_TO_PHYS(kaddr & 0xfffff000), VIRT_TO_PHYS(kaddr & 0xfffff000) | MAP_FLAGS);
    for (i = 0; i < 512; i++)
    {
        if (mbase[i] == 0)
            break;
    }
    mbase[i] = VIRT_TO_PHYS(kaddr & 0xfffff000) | MAP_FLAGS;
    printf("Mapped to: %x\n", mhigh << 20 | i << 12);
}
