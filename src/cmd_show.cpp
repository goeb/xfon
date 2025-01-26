/*
 */

#include <argp.h>
#include <assert.h>
#include <errno.h>
#include <fstream>
#include <iostream>
#include <openssl/asn1.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <string.h>

#include "cli.h"
#include "cmd_show.h"

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

static void hexdump(BIO *out, const unsigned char *data, int length)
{
    for (int i = 0; i < length; i++) {
        int err = BIO_printf(out, "%02X", data[i]);
        if (err <= 0) return;
    }
}

static void hexdump_line(BIO *out, const char *prefix, const unsigned char *data, int length)
{
    BIO_printf(out, "%s", prefix);
    hexdump(out, data, length); // DER-encoded public key
    BIO_printf(out, "\n");
}

/* x509v3 properties
 * ref: https://www.ietf.org/rfc/rfc2459.txt
 * RFC 5280
 *
   Certificate  ::=  SEQUENCE  {
        tbsCertificate       TBSCertificate,
        signatureAlgorithm   AlgorithmIdentifier,
        signatureValue       BIT STRING  }

   TBSCertificate  ::=  SEQUENCE  {
        version         [0]  EXPLICIT Version DEFAULT v1,
        serialNumber         CertificateSerialNumber,
        signature            AlgorithmIdentifier,
        issuer               Name,
        validity             Validity,
        subject              Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version shall be v2 or v3
        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version shall be v2 or v3
        extensions      [3]  EXPLICIT Extensions OPTIONAL
                             -- If present, version shall be v3
        }

   Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }

   CertificateSerialNumber  ::=  INTEGER

   Validity ::= SEQUENCE {
        notBefore      Time,
        notAfter       Time }

   Time ::= CHOICE {
        utcTime        UTCTime,
        generalTime    GeneralizedTime }

   UniqueIdentifier  ::=  BIT STRING

   SubjectPublicKeyInfo  ::=  SEQUENCE  {
        algorithm            AlgorithmIdentifier,
        subjectPublicKey     BIT STRING  }

   Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension

   Extension  ::=  SEQUENCE  {
        extnID      OBJECT IDENTIFIER,
        critical    BOOLEAN DEFAULT FALSE,
        extnValue   OCTET STRING  } *

Extensions
   AuthorityKeyIdentifier ::= SEQUENCE {
      keyIdentifier             [0] KeyIdentifier           OPTIONAL,
      authorityCertIssuer       [1] GeneralNames            OPTIONAL,
      authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }

KeyIdentifier ::= OCTET STRING

SubjectKeyIdentifier ::= KeyIdentifier

      The keyCertSign bit is asserted when the subject public key is
      used for verifying a signature on certificates.  This bit may only
      be asserted in CA certificates.

subjectAltName
      id-ce-subjectAltName OBJECT IDENTIFIER ::=  { id-ce 17 }

      SubjectAltName ::= GeneralNames

      GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName

      GeneralName ::= CHOICE {
           otherName                       [0]     OtherName,
           rfc822Name                      [1]     IA5String,
           dNSName                         [2]     IA5String,
           x400Address                     [3]     ORAddress,
           directoryName                   [4]     Name,
           ediPartyName                    [5]     EDIPartyName,
           uniformResourceIdentifier       [6]     IA5String,
           iPAddress                       [7]     OCTET STRING,
           registeredID                    [8]     OBJECT IDENTIFIER}

      OtherName ::= SEQUENCE {
           type-id    OBJECT IDENTIFIER,
           value      [0] EXPLICIT ANY DEFINED BY type-id }

      EDIPartyName ::= SEQUENCE {
           nameAssigner            [0]     DirectoryString OPTIONAL,
           partyName               [1]     DirectoryString }

      IssuerAltName ::= GeneralNames

*/

static int show_cert(const X509 *cert)
{
    BIO *out;
    //int noerr; // 0=error, 1=success
    out = BIO_new_fd(fileno(stdout), BIO_NOCLOSE);

    // tbsCertificate.version
    long version = X509_get_version(cert);
    BIO_printf(out, "version: %ld\n", version);

    // tbsCertificate.serialNumber
    BIO_printf(out, "serial: ");
    i2a_ASN1_INTEGER(out, X509_get0_serialNumber(cert)); // hexadecimal representation
    BIO_printf(out, "\n");

    // tbsCertificate.signature.algorithm
    const X509_ALGOR *tbs_sigalg = X509_get0_tbs_sigalg(cert);
    BIO_printf(out, "signaturealgorithm: ");
    i2a_ASN1_OBJECT(out, tbs_sigalg->algorithm);
    BIO_printf(out, "\n");
    // TODO tbsCertificate.signature.parameters

    // tbsCertificate.issuer
    BIO_printf(out, "issuer: ");
    X509_NAME_print_ex(out, X509_get_issuer_name(cert), 0, 0);
    BIO_printf(out, "\n");

    // tbsCertificate.validity.notBefore
    BIO_printf(out, "notbefore: ");
    ASN1_TIME_print_ex(out, X509_get0_notBefore(cert), ASN1_DTFLGS_ISO8601);
    BIO_printf(out, "\n");
    // tbsCertificate.validity.notAfter
    BIO_printf(out, "notafter: ");
    ASN1_TIME_print_ex(out, X509_get0_notAfter(cert), ASN1_DTFLGS_ISO8601);
    BIO_printf(out, "\n");

    // tbsCertificate.subject
    BIO_printf(out, "subject: ");
    X509_NAME_print_ex(out, X509_get_subject_name(cert), 0, 0);
    BIO_printf(out, "\n");

    // tbsCertificate.subjectPublicKeyInfo.algorithm
    X509_PUBKEY *pubkey = X509_get_X509_PUBKEY(cert);
    X509_ALGOR *pubkeyalgo;
    const unsigned char *pubkey_bytes;
    int pubkey_length;
    X509_PUBKEY_get0_param(NULL, &pubkey_bytes, &pubkey_length, &pubkeyalgo, pubkey);
    BIO_printf(out, "publickey: ");
    i2a_ASN1_OBJECT(out, pubkeyalgo->algorithm);
    BIO_printf(out, "\n");

    // tbsCertificate.subjectPublicKeyInfo.subjectPublicKey
    hexdump_line(out, "publickey: ", pubkey_bytes, pubkey_length); // DER-encoded public key

    // tbsCertificate.issuerUniqueID
    // tbsCertificate.subjectUniqueID
    const ASN1_BIT_STRING *issuer_uid = NULL;
    const ASN1_BIT_STRING *subject_uid = NULL;
    X509_get0_uids(cert, &issuer_uid, &subject_uid);
    if (issuer_uid) {
        hexdump_line(out, "issueruniqueid: ", issuer_uid->data, issuer_uid->length);
    }
    if (subject_uid) {
        hexdump_line(out, "subjectuniqueid: ", subject_uid->data, subject_uid->length);
    }

    // tbsCertificate.extensions
    const STACK_OF(X509_EXTENSION) *extensions = X509_get0_extensions(cert);
    if (extensions) {
        int i;
        for (i = 0; i < sk_X509_EXTENSION_num(extensions); i++) {
            X509_EXTENSION *extension = sk_X509_EXTENSION_value(extensions, i);
            if (!extension) continue;
            // tbsCertificate.extensions.extnID
            BIO_printf(out, "extensions[%d]:", i);
            ASN1_OBJECT *obj = X509_EXTENSION_get_object(extension);
            char numeric_oid[1024];
            memset(numeric_oid, 0, sizeof(numeric_oid));
            OBJ_obj2txt(numeric_oid, sizeof(numeric_oid)-1, obj, 1);
            // Get the OID short name, in order to know which extension we are dealing with
            int nid = OBJ_obj2nid(obj); // internal ref to openssl OID table
            const char *openssl_short_name = OBJ_nid2sn(nid);
            BIO_printf(out, " %s(%s)", numeric_oid, openssl_short_name);

            // tbsCertificate.extensions.critical
            int critical = X509_EXTENSION_get_critical(extension);
            BIO_printf(out, " critical=%d ", critical);

            // tbsCertificate.extensions.extnValue
            if (0 == strcmp(openssl_short_name, "basicConstraints")) {
                X509V3_EXT_print(out, extension, 0, 0);
            } else if (0 == strcmp(openssl_short_name, "keyUsage")) {
                // TODO: clarify OCTET STRING vs BIT STRING
                // See: X509V3_EXT_print
                const ASN1_OCTET_STRING *value = X509_EXTENSION_get_data(extension);
                hexdump(out, value->data, value->length);
                // TODO: decompose the bitstring (tag 03) to
                // digitalSignature        (0),
                // nonRepudiation          (1),
                // keyEncipherment         (2),
                // dataEncipherment        (3),
                // keyAgreement            (4),
                // keyCertSign             (5),
                // cRLSign                 (6),
                // encipherOnly            (7),
                // decipherOnly            (8)
                // See:
                // STACK_OF(CONF_VALUE) *i2v_ASN1_BIT_STRING(X509V3_EXT_get_nid(NID_key_usage), value, NULL);
            } else {
                const ASN1_OCTET_STRING *value = X509_EXTENSION_get_data(extension);
                hexdump(out, value->data, value->length);
            }
            BIO_printf(out, "\n");
        }
    }

    // signatureAlgorithm
    // signatureValue
    const X509_ALGOR *signature_algo;
    const ASN1_BIT_STRING *signature;
    X509_get0_signature(&signature, &signature_algo, cert);
    // TODO: use a different label for the 2 signaturealgorithm
    // TODO: print signatureAlgorithm.parameters
    BIO_printf(out, "signaturealgorithm: ");
    i2a_ASN1_OBJECT(out, signature_algo->algorithm);
    BIO_printf(out, "\n");
    hexdump_line(out, "signature: ", signature->data, signature->length);

    BIO_free(out);
    return 0;
}

std::string base64_decode(const std::string &base64lines)
{
    fprintf(stderr, "get_pem_cert\n");
    BIO *bio = BIO_new(BIO_s_mem());
    BIO_write(bio, base64lines.data(), base64lines.size());
    BIO *b64_bio = BIO_new(BIO_f_base64());
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL); // Don't require newlines
    BIO_push(b64_bio, bio);
    char one_byte;
    std::string result;
    while (0 < BIO_read(b64_bio, &one_byte, 1)) { // Read byte-by-byte
        result += one_byte;
    } // Once we're done reading decoded data, BIO_read returns -1 even though there's no error

    BIO_free_all(b64_bio); // free all BIO in chain
    return result;
}

/* Read a PEM formatted certificate
 *
 * @first_bytes Bytes already read from the stream
 * @input       Other bytes
 *
 * Returns:
 *    Bytes of the DER encoded certificate
 */
std::string get_pem_cert(const std::string &first_bytes, std::istream &input)
{
    fprintf(stderr, "get_pem_cert\n");
    std::string line;
    std::getline(input, line);
    // complete the line with the first bytes
    line = first_bytes + line;
    printf("line=%s\n", line.c_str());
    std::string base64lines, base64lines_tmp;
    if (line == "-----BEGIN CERTIFICATE-----") {
        fprintf(stderr, "get_pem_cert: got BEGIN CERTIFICATE\n");

        // get all line until END
        while (getline(input, line)) {
            if (line == "-----END CERTIFICATE-----") {
                fprintf(stderr, "get_pem_cert: got END CERTIFICATE\n");
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
 * @first_bytes Bytes already read from the stream
 * @input       Other bytes
 *
 * Returns:
 *    Bytes of the DER encoded certificate
 */
std::string get_der_sequence(const std::string &first_bytes, std::istream &input)
{
    return "TODO get_der_sequence";
}

static int show_cert_file(std::istream &input, const char *filename)
{
    int ret;
    int n_cert = 0;

    fprintf(stderr, "show_cert_file: %s\n", filename);
    while (1) {
        char c;
        if (!input.get(c)) {
            // Cannot get a character
            if (input.eof()) return 0;
            fprintf(stderr, "Cannot get first character of '%s': %s\n", filename, strerror(errno));
            return -1;
        }
        std::string der_bytes;
        if (c == '-') der_bytes = get_pem_cert("-", input);
        else if (c == 0x30) der_bytes = get_der_sequence("\x30", input);
        else {
            fprintf(stderr, "Unknown certificate format: %s\n", strerror(errno));
            return -1;
        }
        // Put the DER bytes in a BIO memory buffer
        BIO *bio = BIO_new(BIO_s_mem());
        BIO_write(bio, der_bytes.data(), der_bytes.size());
        X509 *cert = d2i_X509_bio(bio, NULL);
        if (cert) {
            show_cert(cert);
            X509_free(cert);
            n_cert ++;
        }
        BIO_free(bio);
    }

    if (0 == n_cert) {
        fprintf(stderr, "warning: file has no valid certificate: '%s'\n", filename);
    }
    return 0;
}

int cmd_show(const std::list<std::string> &certificates_paths)
{
    if (certificates_paths.size() == 0) {
        // Take certificates from stdin
        show_cert_file(std::cin, "(stdin)");
    } else {
        for (auto cert_path : certificates_paths) {
            fprintf(stderr, "cmd_show: %s\n", cert_path.c_str());
            std::ifstream ifs(cert_path, std::ifstream::in);
            if (!ifs.good()) {
                fprintf(stderr, "Cannot read from '%s': %s\n", cert_path.c_str(), strerror(errno));
            } else {
                int err = show_cert_file(ifs, cert_path.c_str());
                ifs.close();
            }
        }
    }
    return 0;
}
