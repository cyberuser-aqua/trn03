#include <cparser.h>

#include "cparser_tree.h"
#include "utils.h"

#define RESULT_HREADER write(STDOUT_FILENO, "$$$", 3)

cparser_result_t cparser_cmd_rd_filename_offset_nbytes_dohex(cparser_context_t *context,
                                                             char **filename_ptr,
                                                             uint32_t *offset_ptr,
                                                             uint32_t *nbytes_ptr,
                                                             char **dohex_ptr)
{
    RESULT_HREADER;
    int hex = 0;
    if (dohex_ptr)
    {
        if (strcmp(*dohex_ptr, "h") == 0)
        {
            hex = 1;
        }
    }
    read_text(*filename_ptr, *offset_ptr, *nbytes_ptr, hex);
    return CPARSER_OK;
}
cparser_result_t cparser_cmd_wd_filename_offset_nbytes(cparser_context_t *context,
                                                       char **filename_ptr,
                                                       uint32_t *offset_ptr,
                                                       uint32_t *nbytes_ptr)
{
    char *buff = (char *)malloc(sizeof(char) * (*nbytes_ptr));
    write(STDOUT_FILENO, "wd>", 3);
    read(STDIN_FILENO, buff, *nbytes_ptr);
    write_text(*filename_ptr, *offset_ptr, *nbytes_ptr, buff);
    free(buff);
    return CPARSER_OK;
}
cparser_result_t cparser_cmd_curr_filename(cparser_context_t *context,
                                           char **filename_ptr)
{
    RESULT_HREADER;
    print_cur(*filename_ptr);
    return CPARSER_OK;
}
cparser_result_t cparser_cmd_ru_offset_nbytes_dohex(cparser_context_t *context,
                                                    uint32_t *offset_ptr,
                                                    uint32_t *nbytes_ptr,
                                                    char **dohex_ptr)
{
    RESULT_HREADER;
    int hex = 0;
    if (dohex_ptr)
    {
        if (strcmp(*dohex_ptr, "h") == 0)
        {
            hex = 1;
        }
    }
    if (hex)
        hexdump((void *)*offset_ptr, *nbytes_ptr);
    else
    {
        fflush(stdout);
        printf("%.*s", (int)*nbytes_ptr, (char *)*offset_ptr);
        fflush(stdout);
    }
    return CPARSER_OK;
}
cparser_result_t cparser_cmd_wu_offset_nbytes(cparser_context_t *context,
                                              uint32_t *offset_ptr,
                                              uint32_t *nbytes_ptr)
{
    char *buff = (char *)malloc(sizeof(char) * (*nbytes_ptr));
    write(STDOUT_FILENO, "wu>", 3);
    read(STDIN_FILENO, buff, *nbytes_ptr);
    memcpy((void *)*offset_ptr, buff, *nbytes_ptr);
    free(buff);
    return CPARSER_OK;
}
cparser_result_t cparser_cmd_smap_high_base(cparser_context_t *context,
                                            uint32_t *high_ptr,
                                            uint32_t *base_ptr)
{
    setup_map(*high_ptr, (uint32_t *)*base_ptr);
    return CPARSER_OK;
}
cparser_result_t cparser_cmd_map_kaddr(cparser_context_t *context,
                                       uint32_t *kaddr_ptr)
{
    RESULT_HREADER;
    map(*kaddr_ptr);
    return CPARSER_OK;
}
cparser_result_t cparser_cmd_help_filter(cparser_context_t *context,
                                         char **filter_ptr)
{
    if (filter_ptr)
        return cparser_help_cmd(context->parser, *filter_ptr);
    cparser_help_cmd(context->parser, "help");
    return CPARSER_NOT_OK;
}
cparser_result_t cparser_cmd_exit(cparser_context_t *context)
{
    return cparser_quit(context->parser);
}
