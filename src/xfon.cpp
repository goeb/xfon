
#include <argp.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <string>

#include "config.h"
#include "cli.h"
#include "cmd_diff.h"
#include "cmd_show.h"

const char *argp_program_version = PACKAGE_VERSION;

int parse_cmd(struct argp_state* state, const char *cmd)
{
    struct argp *argp = 0;
    if (!cmd) return -1;
    else if (0 == strcmp(cmd, "diff")) argp = &argp_diff;
    //else if (0 == strcmp(cmd, "grep")) argp = &argp_grep;
    else if (0 == strcmp(cmd, "show")) argp = &argp_show;
    else return -1;

    struct arguments *arguments = (struct arguments *)state->input;
    arguments->command = cmd;

    int argc = state->argc - state->next + 1;
    char **argv = &state->argv[state->next - 1];
    char *argv0 = argv[0];

    std::string progname(state->name);
    progname += " ";
    progname += cmd;
    argv[0] = (char*)progname.c_str();

    argp_parse(argp, argc, argv, ARGP_IN_ORDER, &argc, arguments);

    argv[0] = argv0;
    state->next += argc - 1;
    return 0;
}

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct arguments *arguments = (struct arguments *)state->input;
    int err;

    switch (key) {
    case 'h':
        argp_state_help(state, state->out_stream, ARGP_HELP_STD_HELP);
        break;
    case ARGP_KEY_ARG:
        assert(arg);
        err = parse_cmd(state, arg);
        if (err) argp_error(state, "Not a valid command: %s", arg);
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

    if (arguments.command == "show") return cmd_show(arguments.certificates_paths);
    //else if (command == "show") return cmd_show(arguments.certificates_paths);

    fprintf(stderr, "error invaid command: %s\n", arguments.command.c_str());
    return 0;
}

