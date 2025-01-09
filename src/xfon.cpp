
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "config.h"
#include "cmd_diff.h"
#include "cmd_show.h"
#include "cmd_tree.h"

int usage(int exitcode)
{
    static char doc[] =
        "usage: xfon <command> [<args>]\n"
        "       xfon -h | --help\n"
        "       xfon -V | --version\n"
        "\n"
        "Display information about x509 certificates\n"
        "\n"
        "Supported commands:\n"
        "  diff    Compare two certificates\n"
        "  show    Show contents of certificates\n"
        "  tree    Print a tree of certificates\n"
        "\n"
        "See 'xfon <command> -h' to read about a specific <command>.\n"
        ;
    printf("%s", doc);
    return exitcode;
}

int print_version()
{
    printf("%s\n", PACKAGE_STRING);
    return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
    if (argc < 2) return usage(EXIT_FAILURE);

    if (0 == strcmp(argv[1], "-h") || 0 == strcmp(argv[1], "--help") ) return usage(EXIT_SUCCESS);
    if (0 == strcmp(argv[1], "-V") || 0 == strcmp(argv[1], "--version") ) return print_version();

    const char *cmd = argv[1];
    argc--;
    argv++;
    //if (0 == strcmp(cmd, "diff")) return cmd_show(argc, argv);
    if (0 == strcmp(cmd, "show")) return cmd_show(argc, argv);
    if (0 == strcmp(cmd, "tree")) return cmd_tree(argc, argv);

    fprintf(stderr, "xfon: unrecognized command '%s' (valid commands are: diff, show, tree)\n", cmd);
    return EXIT_FAILURE;
}

