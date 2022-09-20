#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <termios.h>
#include <unistd.h>
#include <string.h>
#include "cparser.h"
#include "cparser_io.h"
#include "cparser_priv.h"
#include "terminal_helper.h"

void term_set_canonical(int amount)
{
    struct termios term;

    tcgetattr(STDIN_FILENO, &term);
    if (amount)
    {
        term.c_lflag |= (ICANON | ECHO);
    }
    else
    {
        term.c_lflag &= ~(ICANON | ECHO);
    }
    sync();
    tcsetattr(STDIN_FILENO, TCSANOW, &term);
}