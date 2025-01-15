/*
 */

#include <argp.h>
#include <assert.h>
#include <errno.h>
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

static void hexdump(BIO *out, const unsigned char *data, int length) {
    for (int i = 0; i < length; i++) {
        int err = BIO_printf(out, "%02X", data[i]);
        if (err <= 0) return;
    }
}

/* x509v3 properties
 * ref: https://www.ietf.org/rfc/rfc2459.txt
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
    BIO_printf(out, "publickey: ");
    hexdump(out, pubkey_bytes, pubkey_length); // DER-encoded public key
    BIO_printf(out, "\n");

    // tbsCertificate.issuerUniqueID
    // tbsCertificate.subjectUniqueID
    // tbsCertificate.extensions

    // signatureAlgorithm
    // signatureValue

    BIO_free(out);
    return 0;
}

static int show_cert_file(const char *path)
{
    BIO *bio;
    int ret;
    X509 *cert;
    int n_cert = 0;

    if (path) {
        bio = BIO_new_file(path, "r");
    } else {
        bio = BIO_new_fd(fileno(stdin), BIO_NOCLOSE);
        path = "(stdin)";
    }

    if (!bio) {
        fprintf(stderr, "BIO_new_file: cannot open '%s': %s\n", path, strerror(errno));
        ret = -1;
        goto error;
    }
    while ((cert = PEM_read_bio_X509(bio, NULL, NULL, NULL))) {
        show_cert(cert);
        X509_free(cert);
        n_cert ++;
    }
    if (0 == n_cert) {
        fprintf(stderr, "warning: file has no valid cetificate: '%s'\n", path);
    }
    ret = 0;
error:
    BIO_free(bio);
    return ret;
}

int cmd_show(const std::list<std::string> &certificates_paths)
{
    if (certificates_paths.size() == 0) {
        // Take certificates from stdin
        fprintf(stderr, "cmd_show: stdin\n");
        show_cert_file(NULL);
    } else {
        for (auto cert_path : certificates_paths) {
            fprintf(stderr, "cmd_show: %s\n", cert_path.c_str());
            show_cert_file(cert_path.c_str());
        }
    }
    return 0;
}
