/*
 */

#include <argp.h>
#include <assert.h>

#include "cli.h"
#include "cmd_tree.h"
#include "hierarchy.h"
#include "journal.h"
#include "load.h"
#include "render_text.h"

struct Arguments_tree {
    std::string command;
    std::list<std::string> certificates_paths;
    bool minimal;
    Arguments_tree(): minimal(false) {}
};

static error_t parse_opt(int key, char* arg, struct argp_state* state)
{
    struct Arguments_tree *arguments = (struct Arguments_tree *)state->input;
    int level;

    switch(key) {
    case 'h':
        argp_state_help(state, state->out_stream, ARGP_HELP_STD_HELP);
        break;
    case 'm':
        arguments->minimal = true;
        break;
    case 'v':
        level = journal.get_log_level();
        level++;
        journal.set_log_level(level);
        break;
    case ARGP_KEY_ARG:
        assert(arg);
        arguments->certificates_paths.push_back(arg);
        break;
    case ARGP_KEY_END:
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static struct argp_option options[] = {
    { "minimal",     'm',  0, 0, "Print a minimal tree", 1 },
    { "properties",  'p',  "PROP[,PROP]...",  0, "Properties to show (implies not minimal)", 1 },
    { "verbose",     'v',  0,                 0, "Be verbose (repeat for more verbosity)", 1 },
    { "",  0, 0,  OPTION_DOC, 0, 1 },
    { 0,  'h', 0, 0, 0, -1 },
    { 0 }
};

static char doc[] =
    "\n"
    "Print a tree x509 certificates.\n"
    "\n"
    "Options:"
    "\v"
    "Certificates can be bundles of several concatenated certificates (DER or PEM)."
    ;

static char args_doc[] = "CERT ...";

/* Entry point for command line parsing */
static struct argp argp = { options, parse_opt, args_doc, doc };

int cmd_tree(int argc, char **argv)
{
    Arguments_tree arguments;

    argp_parse(&argp, argc, argv, ARGP_IN_ORDER, 0, &arguments);

    std::vector<Certificate_with_links> certificates;

    int err = load_certificates(arguments.certificates_paths, certificates);

    if (err) return 1;

    compute_hierarchy(certificates);

    print_tree(certificates, arguments.minimal);

    if (err) return EXIT_FAILURE;
    return EXIT_SUCCESS;
}
