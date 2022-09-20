#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <ctype.h>
#include <cparser.h>

#include "utils.h"
#include "cparser_tree.h"

#ifndef HEXDUMP_COLS
#define HEXDUMP_COLS 16
#endif
#define PAGE_OFFSET 0x80000000U
#define MAP_FLAGS 0b110001111110

#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#define PRINTE(err) write(2, err, strlen(err));
#define VIRT_TO_PHYS(addr) (addr - PAGE_OFFSET)

static int invalid_commandline(void)
{
    PRINTE("ERR: Invalid command line\n");
    exit(1);
}

static void interactive(void)
{
    char filename[16];
    char rw[5];
    unsigned long offset = 0;
    unsigned long nbytes = 0;
    int res = 0;
    int dohex = 0;
    while (res != EOF)
    {
        write(1, "$$$", 3);
        res = scanf("%5s %15s %lu %lu", rw, filename, &offset, &nbytes);
        // printf("%s, %s, %lu, %ld\n", rw, filename, offset, nbytes);
        if (res > 0 && rw[0] == 'H')
        {
            dohex = 1;
        }
        if (res == 4 && strcmp(&rw[dohex], "cur") == 0)
            print_cur("/dev/aqua");
        else if (res == 4 && strcmp(&rw[dohex], "ur") == 0)
        {
            if (dohex)
            {
                hexdump((void *)offset, nbytes);
            }
            else
            {
                printf("%.*s", (int)nbytes, (char *)offset);
            }
        }
        else if (res == 4 && strcmp(&rw[dohex], "uw") == 0)
        {
            char *buff = (char *)malloc(sizeof(char) * nbytes);
            write(1, "u>", 2);
            read(0, buff, nbytes);
            memcpy((void *)offset, buff, nbytes);
            free(buff);
        }
        else if (res == 4 && strcmp(&rw[dohex], "r") == 0)
            read_text(filename, offset, nbytes, dohex);
        else if (res == 4 && strcmp(&rw[dohex], "w") == 0)
        {
            char *buff = (char *)malloc(sizeof(char) * nbytes);
            write(1, ">", 1);
            read(0, buff, nbytes);
            write_text(filename, offset, nbytes, buff);
            free(buff);
        }
        else if (res == 4 && strcmp(&rw[dohex], "smap") == 0)
        {
            setup_map((u_int32_t)offset, (u_int32_t *)nbytes);
        }
        else if (res == 4 && strcmp(&rw[dohex], "map") == 0)
        {
            map((u_int32_t)offset);
        }
        else
            write(1, "E", 1);
        dohex = 0;
    }
}

static void interactive2(void)
{
    int fd = open("/proc/self/mem", O_RDWR);
    printf("/proc/self/mem is at fd=%d\n", fd);
    cparser_t parser = {0};
    parser.cfg.root = &cparser_root;
    parser.cfg.ch_complete = '\t';
    parser.cfg.ch_erase = '\b';
    parser.cfg.ch_del = 127;
    parser.cfg.ch_help = '?';
    parser.cfg.flags = 0;
    parser.cfg.fd = STDOUT_FILENO;
    strcpy(parser.cfg.prompt, "$$$");
    cparser_io_config(&parser);
    cparser_init(&parser.cfg, &parser);
    cparser_run(&parser);
    close(fd);
}

int main(int argc, char **argv, char **envp)
{
    if (argc > 1)
    {
        if (strcmp(argv[1], "cur") == 0)
        {
            print_cur("/dev/aqua");
            return 0;
        }
        else if (strcmp(argv[1], "interactive") == 0)
        {
            interactive2();
            return 0;
        }
    }
    if (argc < 5)
        invalid_commandline();
    char *filename = argv[1];
    char *rw = argv[2];
    unsigned long offset = strtoul(argv[3], NULL, 10);
    if (offset < 0)
        invalid_commandline();
    long nbytes = strtol(argv[4], NULL, 10);
    if (nbytes < 0)
        invalid_commandline();

    if (strcmp(rw, "r") == 0)
        read_text(filename, offset, nbytes, 0);
    else if (strcmp(rw, "w") == 0 && argc == 6)
        write_text(filename, offset, nbytes, argv[5]);
    else
        invalid_commandline();
    return 0;
}
