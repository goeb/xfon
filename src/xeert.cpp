
#include <argp.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "config.h"
#include "cli.h"
#include "cmd_diff.h"

const char *argp_program_version = PACKAGE_VERSION;

static void parse_cmd_grep(struct argp_state* state)
{
    printf("parse_cmd_grep TODO\n");
}

static void parse_cmd_show(struct argp_state* state)
{
    printf("parse_cmd_show TODO\n");
}

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct arguments *arguments = (struct arguments *)state->input;

    switch (key) {
    case 'h':
        argp_state_help(state, state->out_stream, ARGP_HELP_STD_HELP);
        break;
    case ARGP_KEY_ARG:
        assert(arg);
        arguments->command = arg;
        if (0 == strcmp(arg, "diff")) {
            parse_cmd_diff(state);
        } else if (0 == strcmp(arg, "grep")) {
            parse_cmd_grep(state);
        } else if (0 == strcmp(arg, "show")) {
            parse_cmd_show(state);
        } else {
            argp_error(state, "Not a valid command: %s", arg);
        }
        break;
    case ARGP_KEY_END:
        if (arguments->command.empty()) {
            argp_error(state, "Missing command");
        }
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
	return 0;
}

static char doc[] =
    "\n"
    "Display information about x509 certificates\n"
    "\n"
    "Supported commands:\n"
    "  diff    Compare two certificates\n"
    "  grep    Search for patterns in certificates\n"
    "  show    Show contents of certificates\n"
    "\n"
    "Options:"
    "\v"
    "See 'xeert <command> -h' to read about a specific <command>."
    ;

static char args_doc[] = "<command> <args>";

static struct argp_option options[] = {
    { 0,  'h', 0, 0, NULL, -1 },
    { 0 }
};

static struct argp argp = { options, parse_opt, args_doc, doc };

int main(int argc, char **argv)
{
	struct arguments arguments;

    argp_parse(&argp, argc, argv, ARGP_IN_ORDER, 0, &arguments);

	return 0;
}

