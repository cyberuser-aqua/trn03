#if !defined(TERMINAL_HERLPER)
#define TERMINAL_HERLPER
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
void term_set_canonical(int enable);
#endif // TERMINAL_HERLPER
