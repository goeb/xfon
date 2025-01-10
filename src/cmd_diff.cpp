/*
 */

#include <argp.h>
#include <assert.h>
#include <stdio.h>

#include "cli.h"
#include "cmd_diff.h"

static error_t parse_opt(int key, char* arg, struct argp_state* state)
{
    struct arguments *arguments = (struct arguments *)state->input;

    switch(key) {
    case 'h':
        argp_state_help(state, state->out_stream, ARGP_HELP_STD_HELP);
        break;
    case ARGP_KEY_ARG:
        if (arguments->certificates_paths.size() >=2 ){
            argp_error(state, "Too many certificates. Please specify exactly 2.");
        }
        assert(arg);
        arguments->certificates_paths.push_back(arg);
        break;
    case ARGP_KEY_END:
        if (arguments->certificates_paths.size() != 2) {
            argp_error(state, "Please specify exactly 2 certificates (%lu given)",
                       arguments->certificates_paths.size());
        }
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static struct argp_option options[] = {
    { 0,  'h', 0, 0, "Same as --help", -1 },
    { 0 }
};

static char doc[] =
    "\n"
    "Compare certificates CERT1 and CERT2.\n"
    "\n"
    "Options:"
    ;

static char args_doc[] = "CERT1 CERT2";

static struct argp argp = { options, parse_opt, args_doc, doc };

void parse_cmd_diff(struct argp_state* state)
{
    struct arguments *arguments = (struct arguments *)state->input;

    int argc = state->argc - state->next + 1;
    char **argv = &state->argv[state->next - 1];
    char *argv0 = argv[0];

    std::string progname(state->name);
    progname += " diff";
    argv[0] = (char*)progname.c_str();

    argp_parse(&argp, argc, argv, ARGP_IN_ORDER, &argc, arguments);

    argv[0] = argv0;
    state->next += argc - 1;
    return;
}
