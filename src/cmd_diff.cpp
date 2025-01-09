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
    { 0,  'h', 0, 0, 0, -1 },
    { 0 }
};

static char doc[] =
    "\n"
    "Compare certificates CERT1 and CERT2.\n"
    "\n"
    "Options:"
    ;

static char args_doc[] = "CERT1 CERT2";

/* Entry point for command line parsing */
struct argp argp_diff = { options, parse_opt, args_doc, doc };
