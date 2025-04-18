/*
 */

#include <argp.h>
#include <assert.h>
#include <errno.h>
#include <fstream>
#include <iostream>
#include <stdio.h>
#include <string.h>

#include "cli.h"
#include "cmd_show.h"
#include "der_decode_x509.h"
#include "hierarchy.h"
#include "journal.h"
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
struct argp argp_show = { options, parse_opt, args_doc, doc };


/* Read a PEM formatted certificate
 *
 * Returns:
 *    Bytes of the DER encoded certificate
 */
OctetString get_pem_cert(std::istream &input)
{
    std::string line;
    std::getline(input, line);
    std::string base64lines, base64lines_tmp;
    if (line == "-----BEGIN CERTIFICATE-----") {

        // get all line until END
        while (getline(input, line)) {
            if (line == "-----END CERTIFICATE-----") {
                base64lines = base64lines_tmp;
                break;
            }
            else base64lines_tmp += line;
        }
        if (input.fail()) {
            LOGERROR("get_pem_cert: input error");
            return OctetString();
        }
    } else {
        LOGERROR("get_pem_cert: invalid first line");
        return OctetString();
    }
    // convert from base64
    OctetString bytes = base64_decode(base64lines);
    return bytes;
}

/* Read a PEM formatted certificate
 *
 * Returns:
 *    Bytes of the DER encoded certificate
 */
OctetString get_der_sequence(std::istream &input)
{
    OctetString der_bytes;

    // Get the length of the SEQUENCE (DER)
    // - either the first byt, if < 128
    // - or the following bytes (big endian)
    unsigned char buffer[2];
    input.read((char *)buffer, 2);
    if (!input.good()) {
        LOGERROR("Cannot get first 2 bytes of DER SEQUENCE: %s", strerror(errno));
        return OctetString();
    }
    der_bytes.append(buffer, 2);
    int data_length = 0;
    if (buffer[1] & 0x80) {
        // Length encoded on multibytes, big-endian
        int n_bytes = (unsigned char)buffer[1] & 0x7f;
        for (int i=0; i<n_bytes; i++) {
            unsigned char c;
            input.read((char*)&c, 1);
            if (!input.good()) {
                LOGERROR("Cannot get next byte of DER SEQUENCE: %s", strerror(errno));
                return OctetString();
            }
            if (data_length > (INT_MAX >> 8 )) {
                // unsigned integer overflow
                LOGERROR("Length of DER SEQUENCE overflow");
                return OctetString();
            }
            der_bytes.append(&c, 1);
            data_length = (data_length << 8) + (unsigned char)c;
        }
    } else {
        data_length = (unsigned char)buffer[1];
    }

    // Read the SEQUENCE contents
    unsigned char *contents = (unsigned char*)malloc(data_length);
    input.read((char *)contents, data_length);
    if (!input.good()) {
        LOGERROR("Cannot get %d bytes of contents DER SEQUENCE: %s", data_length, strerror(errno));
        free(contents);
        return OctetString();
    }
    der_bytes.append(contents, data_length);
    free(contents);

    return der_bytes;
}

static int show_cert_file(std::istream &input, const char *filename)
{
    LOGDEBUG("%s", filename);
    size_t index = 0;
    std::list<Certificate> certificates;
    while (1) {
        int c = input.peek();
        if (c == EOF) {
            // Cannot get a character
            if (input.eof()) break;
            LOGERROR("Cannot get first character of '%s': %s", filename, strerror(errno));
            return -1;
        }
        OctetString der_bytes;
        if (c == '-') {
            der_bytes = get_pem_cert(input);
        }
        else if (c == 0x30) der_bytes = get_der_sequence(input);
        else {
            LOGERROR("Unknown certificate format: %s", filename);
            return -1;
        }
        if (der_bytes.empty()) {
            LOGERROR("Could not read PEM/DER from '%s'", filename);
            return -1;
        }

        Certificate cert;
        cert.filename = filename;
        cert.index_in_file = index;
        int err = der_decode_x509_certificate(der_bytes, cert);
        if (err) return -1;
        certificates.push_back(cert);
        index++;
    }

    if (certificates.empty()) {
        LOGERROR("No certificate read from '%s'", filename);
        return -1;
    }

    std::list<Certificate_with_links> certs = compute_hierarchy(certificates);

    for (auto const &cert: certs) {
        IndentationContext indent_ctx;
        indent_ctx.has_child = false;
        //indent_ctx.has_child = false;
        //indent_ctx.lineage.push_back(false);
        //indent_ctx.lineage.push_back(true);
        //indent_ctx.lineage.push_back(false);
        printf("%s", to_string(cert, indent_ctx).c_str());
    }

    return 0;
}

int cmd_show(const std::list<std::string> &certificates_paths)
{
    int err = 0;
    if (certificates_paths.size() == 0) {
        // Take certificates from stdin
        err = show_cert_file(std::cin, "(stdin)");

    } else {
        for (auto cert_path : certificates_paths) {
            std::ifstream ifs(cert_path, std::ifstream::in);
            if (!ifs.good()) {
                LOGERROR("Cannot read from '%s': %s", cert_path.c_str(), strerror(errno));
                err = 1;
                break;
            } else {
                err = show_cert_file(ifs, cert_path.c_str());
                if (err) break;
                ifs.close();
            }
        }
    }
    if (err) return 1;
    return 0;
}
