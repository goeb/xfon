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
#include "oid_name.h"
#include "parse_x509.h"


static error_t parse_opt(int key, char* arg, struct argp_state* state)
{
    struct arguments *arguments = (struct arguments *)state->input;

    switch(key) {
    case 'h':
        argp_state_help(state, state->out_stream, ARGP_HELP_STD_HELP);
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
std::string get_pem_cert(std::istream &input)
{
    //fprintf(stderr, "debug: get_pem_cert\n");
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
            fprintf(stderr, "get_pem_cert: input error\n");
            return "";
        }
    } else {
        fprintf(stderr, "get_pem_cert: invalid first line\n");
        return "";
    }
    // convert from base64
    std::string bytes = base64_decode(base64lines);
    return bytes;
}

/* Read a PEM formatted certificate
 *
 * Returns:
 *    Bytes of the DER encoded certificate
 */
std::string get_der_sequence(std::istream &input)
{
    //fprintf(stderr, "debug: get_der_sequence\n");
    std::string der_bytes;

    // Get the length of the SEQUENCE (DER)
    // - either the first byt, if < 128
    // - or the following bytes (big endian)
    char buffer[2];
    input.read(buffer, 2);
    if (!input.good()) {
        fprintf(stderr, "Cannot get first 2 bytes of DER SEQUENCE: %s\n", strerror(errno));
        return "";
    }
    der_bytes.append(buffer, 2);
    int data_length = 0;
    if (buffer[1] & 0x80) {
        // Length encoded on multibytes, big-endian
        int n_bytes = (unsigned char)buffer[1] & 0x7f;
        for (int i=0; i<n_bytes; i++) {
            char c;
            input.read(&c, 1);
            if (!input.good()) {
                fprintf(stderr, "Cannot get next byte of DER SEQUENCE: %s\n", strerror(errno));
                return "";
            }
            if (data_length > (INT_MAX >> 8 )) {
                // unsigned integer overflow
                fprintf(stderr, "Length of DER SEQUENCE overflow\n");
                return "";
            }
            der_bytes.append(&c, 1);
            data_length = (data_length << 8) + (unsigned char)c;
        }
        //fprintf(stderr, "debug: multi-byte length=0x%x\n", data_length);
    } else {
        data_length = (unsigned char)buffer[1];
        //fprintf(stderr, "debug: single-byte length=0x%x\n", data_length);
    }

    // Read the SEQUENCE contents
    char *contents = (char*)malloc(data_length);
    input.read(contents, data_length);
    if (!input.good()) {
        fprintf(stderr, "Cannot get %d bytes of contents DER SEQUENCE: %s\n", data_length, strerror(errno));
        free(contents);
        return "";
    }
    der_bytes.append(contents, data_length);
    free(contents);

    return der_bytes;
}

static int show_cert_file(std::istream &input, const char *filename)
{
    fprintf(stderr, "show_cert_file: %s\n", filename);
    std::list<Certificate*> certificates;
    while (1) {
        int c = input.peek();
        if (c == EOF) {
            // Cannot get a character
            if (input.eof()) break;
            fprintf(stderr, "Cannot get first character of '%s': %s\n", filename, strerror(errno));
            return -1;
        }
        std::string der_bytes;
        if (c == '-') der_bytes = get_pem_cert(input);
        else if (c == 0x30) der_bytes = get_der_sequence(input);
        else {
            fprintf(stderr, "Unknown certificate format: %s\n", filename);
            return -1;
        }
        if (!der_bytes.size()) {
            fprintf(stderr, "Could not read PEM/DER from '%s'\n", filename);
            return -1;
        }

        Certificate *cert = new Certificate();
        int err = x509_parse_der(der_bytes, *cert);
        if (err) return -1;
        certificates.push_back(cert);
    }

    if (certificates.empty()) {
        fprintf(stderr, "No certificate read from '%s'\n", filename);
        return -1;
    }

    for (auto const &cert: certificates) {
        for (auto const &it: cert->properties) {
            printf("%s: %s\n", it.first.c_str(), it.second->to_string().c_str());
        }
        for (auto const &it: cert->extensions) {
            std::string oidname = oid_get_name(it.first.c_str());
            const char *longname_prefix = "tbsCertificate.extensions";
            printf("%s.%s.critical: %d\n", longname_prefix, oidname.c_str(), it.second.critical);
            //printf("debug: it.second.extn_value=%p\n", it.second.extn_value);
            //printf("debug: it.second.extn_value: type %d\n", it.second.extn_value->get_type());
            printf("%s.%s.extnValue: %s\n", longname_prefix, oidname.c_str(), it.second.extn_value->to_string().c_str());
        }

        x509_free(*cert);
        delete cert;
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
                fprintf(stderr, "Cannot read from '%s': %s\n", cert_path.c_str(), strerror(errno));
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
