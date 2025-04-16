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
#include "oid_name.h"
#include "render_text.h"


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
OctetString get_pem_cert(std::istream &input)
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
            return OctetString();
        }
    } else {
        fprintf(stderr, "get_pem_cert: invalid first line\n");
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
    //fprintf(stderr, "debug: get_der_sequence\n");
    OctetString der_bytes;

    // Get the length of the SEQUENCE (DER)
    // - either the first byt, if < 128
    // - or the following bytes (big endian)
    unsigned char buffer[2];
    input.read((char *)buffer, 2);
    if (!input.good()) {
        fprintf(stderr, "Cannot get first 2 bytes of DER SEQUENCE: %s\n", strerror(errno));
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
                fprintf(stderr, "Cannot get next byte of DER SEQUENCE: %s\n", strerror(errno));
                return OctetString();
            }
            if (data_length > (INT_MAX >> 8 )) {
                // unsigned integer overflow
                fprintf(stderr, "Length of DER SEQUENCE overflow\n");
                return OctetString();
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
    unsigned char *contents = (unsigned char*)malloc(data_length);
    input.read((char *)contents, data_length);
    if (!input.good()) {
        fprintf(stderr, "Cannot get %d bytes of contents DER SEQUENCE: %s\n", data_length, strerror(errno));
        free(contents);
        return OctetString();
    }
    der_bytes.append(contents, data_length);
    free(contents);

    return der_bytes;
}

static int show_cert_file(std::istream &input, const char *filename)
{
    fprintf(stderr, "show_cert_file: %s\n", filename);
    std::list<Certificate> certificates;
    while (1) {
        int c = input.peek();
        if (c == EOF) {
            // Cannot get a character
            if (input.eof()) break;
            fprintf(stderr, "Cannot get first character of '%s': %s\n", filename, strerror(errno));
            return -1;
        }
        OctetString der_bytes;
        if (c == '-') {
            der_bytes = get_pem_cert(input);
            //fprintf(stderr, "xfhdebug: xfh.der\n");
            //FILE *f = fopen("xfh.der", "w");
            //fwrite(der_bytes.data(), der_bytes.size(), 1, f);
            //fclose(f);
        }
        else if (c == 0x30) der_bytes = get_der_sequence(input);
        else {
            fprintf(stderr, "Unknown certificate format: %s\n", filename);
            return -1;
        }
        if (der_bytes.empty()) {
            fprintf(stderr, "Could not read PEM/DER from '%s'\n", filename);
            return -1;
        }

        Certificate cert;
        int err = der_decode_x509_certificate(der_bytes, cert);
        if (err) return -1;
        certificates.push_back(cert);
    }

    if (certificates.empty()) {
        fprintf(stderr, "No certificate read from '%s'\n", filename);
        return -1;
    }

    for (auto const &cert: certificates) {
        printf("tbsCertificate.subject: %s\n", to_string(cert.tbs_certificate.subject).c_str());
        printf("tbsCertificate.issuer: %s\n", to_string(cert.tbs_certificate.issuer).c_str());
        printf("tbsCertificate.validity.notBefore: %s\n", cert.tbs_certificate.validity.not_before.c_str());
        printf("tbsCertificate.validity.notAfter: %s\n", cert.tbs_certificate.validity.not_before.c_str());

        // TODO extensions
        for (auto it: cert.tbs_certificate.extensions.items) {
            if (it.first == oid_get_id("id-ce-basicConstraints")) {
                BasicConstraints basic_constraints = std::any_cast<BasicConstraints>(it.second.extn_value);
                printf("basicConstraints: %s\n", to_string(basic_constraints).c_str());
            }
        }
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
