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

static error_t parse_opt(int key, char* arg, struct argp_state* state)
{
    struct arguments *arguments = (struct arguments *)state->input;
    int level;

    switch(key) {
    case 'h':
        argp_state_help(state, state->out_stream, ARGP_HELP_STD_HELP);
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

/* TODO
 * Categories
 * --properties
 *     minimal     Subject, (Issuer if style list)
 *     simple      + Validity
 *     detail      + signatureAlgorithm, SubjectPublicKeyInfo.algorithm
 *     all         + the rest
 *     subject,serial,notbefore
 */

static struct argp_option options[] = {
    { "format",      'f', "FORMAT", 0, "text|json (default: text)", 1 },
    { "style",         0, "STYLE",  0, "tree|list (default: tree)", 1 },
    { "properties",  'p', "PROP[,PROP]...",  0, "Properties to show", 1 },
    { "verbose",     'v', 0,                 0, "Be verbose (repeat for more verbosity)", 1 },
    { "",  0, 0,  OPTION_DOC, 0, 1 },
    { 0,  'h', 0, 0, 0, -1 },
    { 0 }
};

static char doc[] =
    "\n"
    "Show x509 certificates.\n"
    "\n"
    "Options:"
    "\v"
    "Certificates can be bundles of several concatenated certificates."
    ;

static char args_doc[] = "CERT ...";

/* Entry point for command line parsing */
struct argp argp_tree = { options, parse_opt, args_doc, doc };

int cmd_tree(const std::list<std::string> &certificates_paths)
{
    std::vector<Certificate_with_links> certificates;

    int err = load_certificates(certificates_paths, certificates);

    if (err) return 1;

    compute_hierarchy(certificates);

    print_tree(certificates);

    if (err) return EXIT_FAILURE;
    return EXIT_SUCCESS;
}
