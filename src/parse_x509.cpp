
/* Parse x509 implementation using openssl (libcrypto)
 */

#include <sstream>
#include <openssl/asn1.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "parse_x509.h"

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
        extnValue   OCTET STRING  }

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


std::string hexdump(const unsigned char *data, int length)
{
    std::string result;
    char buffer[3];
    for (int i = 0; i < length; i++) {
        sprintf(buffer, "%02X", data[i]);
        result += buffer;
    }
    return result;
}
std::string hexdump(const std::string &str)
{
    return hexdump((const unsigned char *)str.data(), str.size());
}


/**
 * @brief Convert a ASN1_INTEGER to a string
 * @param number
 * @return hexadecimal notation
 */
static std::string to_string(const ASN1_INTEGER *number)
{
    std::string result;
    if (!number) return "";
    if (number->type & V_ASN1_NEG) result = "-"; // negative value
    if (!number->length) result += "00";
    else result += hexdump(number->data, number->length);
    return result;
}

static std::string to_string(const ASN1_TYPE *stuff)
{
    if (!stuff) return "";
    if (stuff->type == V_ASN1_BOOLEAN) return stuff->value.boolean?"TRUE":"FALSE";
    if (stuff->type == V_ASN1_NULL) return "NULL";
    if (stuff->type == V_ASN1_INTEGER) return to_string(stuff->value.integer);
    if (stuff->type != V_ASN1_OCTET_STRING || ! stuff->value.octet_string ) {
        fprintf(stderr, "Cannot convert ASN1_TYPE to string (type=%d)\n", stuff->type);
        return "";
    }
    const unsigned char *data = ASN1_STRING_get0_data(stuff->value.octet_string);
    int length = ASN1_STRING_length(stuff->value.octet_string);
    return hexdump(data, length);
}

/**
 * @brief Get the length of an DER-encoded ASN.1 type
 * @param der_data
 * @param der_length
 * @return
 */
static int der_get_data_length(unsigned char *der_data, int der_length)
{
    int length = 0;
    if (!der_data) return -1;
    if (der_length < 2) return -1;
    if (der_data[1] & 0x80) {
        // Length encoded on multibytes, big-endian
        int n_bytes = (unsigned char)der_data[1] & 0x7f;
        if (n_bytes+2 > der_length) return -1;

        for (int i=2; i<n_bytes+2; i++) {
            if (length > (INT_MAX >> 8 )) {
                // unsigned integer overflow
                fprintf(stderr, "Length of DER SEQUENCE overflow\n");
                return -1;
            }
            length = (length << 8) + der_data[i];
        }
    } else {
        // length encoded on a single byte
        length = der_data[1];
    }
    return length;
}

static std::string get_bio_mem_string(BIO *buffer) {
    char *ptr;
    long datalen = BIO_get_mem_data(buffer, &ptr);
    if (datalen < 0 || !ptr) {
        // error
        fprintf(stderr, "BIO_get_mem_data error\n");
        return "";
    }
    return std::string(ptr, datalen);
}

#if 0
static std::string decode_octet_string(unsigned char *der_data, int der_length)
{
    if (!der_data) return "<invalid-octet-string>";
    if (der_length < 2) return "<invalid-octet-string>";
    int length = der_get_data_length(der_data, der_length);
    if (length < 0)...

}
#endif
static void get_extensions(const X509 *cert, std::map<ObjectIdentifier, Extension> &extensions)
{
    const STACK_OF(X509_EXTENSION) *ptr_extensions = X509_get0_extensions(cert);
    if (!ptr_extensions) return;

    for (int i = 0; i < sk_X509_EXTENSION_num(ptr_extensions); i++) {
        X509_EXTENSION *ptr_extension = sk_X509_EXTENSION_value(ptr_extensions, i);
        if (!ptr_extension) continue;

        // tbsCertificate.extensions.extnID
        ASN1_OBJECT *obj = X509_EXTENSION_get_object(ptr_extension);
        char numeric_oid[1024];
        memset(numeric_oid, 0, sizeof(numeric_oid));
        int err = OBJ_obj2txt(numeric_oid, sizeof(numeric_oid)-1, obj, 1);
        if (err < 0) {
            fprintf(stderr, "Cannot get extnID (tbsCertificate.extensions[%d])\n", i);
        } else if (extensions.count(numeric_oid)) {
            // OID already registered (a certificate should not have several extensions with the same OID)
            fprintf(stderr, "extnID '%s' already registered (tbsCertificate.extensions[%d])\n", numeric_oid, i);
        } else {
            Extension ext;
            // critical
            ext.critical = X509_EXTENSION_get_critical(ptr_extension);

            // extnValue
            const ASN1_OCTET_STRING *extn_value = X509_EXTENSION_get_data(ptr_extension);
            if (!extn_value) {
                fprintf(stderr, "Cannot get extnValue (tbsCertificate.extensions[%d])\n", i);
            } else {
                // This octet string encodes another structure that depends on extnID
                ext.extn_value = std::string((const char*)extn_value->data, extn_value->length);
                extensions[numeric_oid] = ext;
            }
        }
    }
}

static int populate_map(const X509 *cert, Certificate &result)
{
    std::ostringstream str_stream;
    int err;
    std::string value;
    BIO *buffer = BIO_new(BIO_s_mem());

    // tbsCertificate.version
    long version = X509_get_version(cert);
    str_stream.str("");
    str_stream << version;
    result.properties["tbsCertificate.version"] = str_stream.str();

    // tbsCertificate.serialNumber
    const ASN1_INTEGER *serial = X509_get0_serialNumber(cert);
    result.properties["tbsCertificate.serialNumber"] = to_string(serial);

    // tbsCertificate.signature.algorithm
    const X509_ALGOR *tbs_sigalg = X509_get0_tbs_sigalg(cert);
    BIO_reset(buffer);
    err = i2a_ASN1_OBJECT(buffer, tbs_sigalg->algorithm);
    if (err < 0) {
        fprintf(stderr, "Error while serializing tbsCertificate.signature.algorithm\n");
        value = "";
    } else value = get_bio_mem_string(buffer);
    result.properties["tbsCertificate.signature.algorithm"] = value;

    // tbsCertificate.signature.parameters
    result.properties["tbsCertificate.signature.parameters"] = to_string(tbs_sigalg->parameter);

    // tbsCertificate.issuer
    X509_NAME *issuer_name = X509_get_issuer_name(cert);
    BIO_reset(buffer);
    err = X509_NAME_print_ex(buffer, issuer_name, 0, 0);
    if (err < 0) {
        fprintf(stderr, "Error while serializing tbsCertificate.issuer\n");
        value = "";
    } else value = get_bio_mem_string(buffer);
    result.properties["tbsCertificate.issuer"] = value;

    // tbsCertificate.validity.notBefore
    BIO_reset(buffer);
    err = ASN1_TIME_print_ex(buffer, X509_get0_notBefore(cert), ASN1_DTFLGS_ISO8601);
    if (err < 0) {
        fprintf(stderr, "Error while serializing tbsCertificate.issuer\n");
        value = "";
    } else value = get_bio_mem_string(buffer);
    result.properties["tbsCertificate.validity.notBefore"] = value;

    // tbsCertificate.validity.notAfter
    BIO_reset(buffer);
    err = ASN1_TIME_print_ex(buffer, X509_get0_notAfter(cert), ASN1_DTFLGS_ISO8601);
    if (err < 0) {
        fprintf(stderr, "Error while serializing tbsCertificate.issuer\n");
        value = "";
    } else value = get_bio_mem_string(buffer);
    result.properties["tbsCertificate.validity.notAfter"] = value;

    // tbsCertificate.subject
    BIO_reset(buffer);
    X509_NAME *subject_name = X509_get_subject_name(cert);
    err = X509_NAME_print_ex(buffer, subject_name, 0, 0);
    if (err < 0) {
        fprintf(stderr, "Error while serializing tbsCertificate.issuer\n");
        value = "";
    } else value = get_bio_mem_string(buffer);
    result.properties["tbsCertificate.subject"] = value;

    // tbsCertificate.subjectPublicKeyInfo.algorithm
    X509_PUBKEY *pubkey = X509_get_X509_PUBKEY(cert);
    X509_ALGOR *pubkeyalgo;
    const unsigned char *pubkey_bytes;
    int pubkey_length;
    X509_PUBKEY_get0_param(NULL, &pubkey_bytes, &pubkey_length, &pubkeyalgo, pubkey);
    BIO_reset(buffer);
    err = i2a_ASN1_OBJECT(buffer, pubkeyalgo->algorithm);
    if (err < 0) {
        fprintf(stderr, "Error while serializing tbsCertificate.subjectPublicKeyInfo.algorithm\n");
        value = "";
    } else value = get_bio_mem_string(buffer);
    result.properties["tbsCertificate.subjectPublicKeyInfo.algorithm"] = value;

    // tbsCertificate.subjectPublicKeyInfo.subjectPublicKey
    result.properties["tbsCertificate.subjectPublicKeyInfo.subjectPublicKey"] = hexdump(pubkey_bytes, pubkey_length); // DER-encoded public key

    // tbsCertificate.issuerUniqueID
    // tbsCertificate.subjectUniqueID
    const ASN1_BIT_STRING *issuer_uid = NULL;
    const ASN1_BIT_STRING *subject_uid = NULL;
    X509_get0_uids(cert, &issuer_uid, &subject_uid);
    if (issuer_uid) {
        result.properties["tbsCertificate.issuerUniqueID"] = hexdump(issuer_uid->data, issuer_uid->length);
    }
    if (subject_uid) {
        result.properties["tbsCertificate.subjectUniqueID"] = hexdump(subject_uid->data, subject_uid->length);
    }

    // tbsCertificate.extensions
    get_extensions(cert, result.extensions);

    // signatureAlgorithm
    // signatureValue
    const X509_ALGOR *signature_algo;
    const ASN1_BIT_STRING *signature;
    X509_get0_signature(&signature, &signature_algo, cert);
    // TODO: use a different label for the 2 signaturealgorithm
    // TODO: print signatureAlgorithm.parameters
    BIO_reset(buffer);
    err = i2a_ASN1_OBJECT(buffer, signature_algo->algorithm);
    if (err < 0) {
        fprintf(stderr, "Error while serializing signatureAlgorithm\n");
        value = "";
    } else value = get_bio_mem_string(buffer);
    result.properties["signatureAlgorithm"] = value;
    result.properties["signatureValue"] = hexdump(signature->data, signature->length);

    BIO_free(buffer);
    return 0;
}

/**
 * @brief Parse DER encoded bytes into a Certificate
 * @param der_bytes
 * @param cert
 * @return  0 success
 *         -1 error
 * On success, the Certificate.opaque pointer should freed by the caller
 * using x509_free().
 */
int x509_parse_der(const std::string &der_bytes, Certificate &cert)
{
    int retcode = -1; // 0=success, -1=error
    std::map<std::string, std::string> result;
    // Put the DER bytes in a BIO memory buffer
    BIO *bio = BIO_new(BIO_s_mem());
    BIO_write(bio, der_bytes.data(), der_bytes.size());
    X509 *ptr_cert = d2i_X509_bio(bio, NULL);
    if (ptr_cert) {
        populate_map(ptr_cert, cert);
        cert.opaque = ptr_cert;
        retcode = 0;
    }
    BIO_free(bio);
    return retcode;
}

void x509_free(Certificate &cert)
{
    cert.properties.clear();
    cert.extensions.clear();
    X509_free((X509 *)cert.opaque);
}

std::string base64_decode(const std::string &base64lines)
{
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
