
/* Parse x509 implementation using openssl (libcrypto)
 */

#include <sstream>
#include <openssl/asn1.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "parse_x509.h"

static std::string hexdump(const unsigned char *data, int length)
{
    std::string result;
    char buffer[3];
    for (int i = 0; i < length; i++) {
        sprintf(buffer, "%02X", data[i]);
        result += buffer;
    }
    return result;
}

static int populate_map(const X509 *cert, std::map<std::string, std::string> &result)
{
    std::ostringstream string_value;
    char *ptr;
    long datalen;
    BIO *buffer = BIO_new(BIO_s_mem());

    // tbsCertificate.version
    long version = X509_get_version(cert);
    string_value << version;
    result["tbsCertificate.version"] = string_value.str();
    string_value.str("");

    // tbsCertificate.serialNumber
    i2a_ASN1_INTEGER(buffer, X509_get0_serialNumber(cert)); // hexadecimal representation
    datalen = BIO_get_mem_data(buffer, &ptr);
    if (datalen < 0 || !ptr) {
        fprintf(stderr, "BIO_get_mem_data error\n");
        BIO_free(buffer);
        return -1;
    }
    result["tbsCertificate.serialNumber"] = std::string(ptr, datalen);
    BIO_reset(buffer);

    // tbsCertificate.signature.algorithm
    const X509_ALGOR *tbs_sigalg = X509_get0_tbs_sigalg(cert);
    i2a_ASN1_OBJECT(buffer, tbs_sigalg->algorithm);
    datalen = BIO_get_mem_data(buffer, &ptr);
    if (datalen < 0 || !ptr) {
        // error
        fprintf(stderr, "BIO_get_mem_data error 2\n");
        BIO_free(buffer);
        return -1;
    }
    result["tbsCertificate.signature.algorithm"] = std::string(ptr, datalen);
    BIO_reset(buffer);
    // TODO tbsCertificate.signature.parameters

    // tbsCertificate.issuer
    X509_NAME_print_ex(buffer, X509_get_issuer_name(cert), 0, 0);
    datalen = BIO_get_mem_data(buffer, &ptr);
    if (datalen < 0 || !ptr) {
        // error
        fprintf(stderr, "BIO_get_mem_data error 2\n");
        BIO_free(buffer);
        return -1;
    }
    result["tbsCertificate.issuer"] = std::string(ptr, datalen);
    BIO_reset(buffer);

    // tbsCertificate.validity.notBefore
    ASN1_TIME_print_ex(buffer, X509_get0_notBefore(cert), ASN1_DTFLGS_ISO8601);
    datalen = BIO_get_mem_data(buffer, &ptr);
    if (datalen < 0 || !ptr) {
        // error
        fprintf(stderr, "BIO_get_mem_data error 2\n");
        BIO_free(buffer);
        return -1;
    }
    result["tbsCertificate.validity.notBefore"] = std::string(ptr, datalen);
    BIO_reset(buffer);

    // tbsCertificate.validity.notAfter
    ASN1_TIME_print_ex(buffer, X509_get0_notAfter(cert), ASN1_DTFLGS_ISO8601);
    datalen = BIO_get_mem_data(buffer, &ptr);
    if (datalen < 0 || !ptr) {
        // error
        fprintf(stderr, "BIO_get_mem_data error 2\n");
        BIO_free(buffer);
        return -1;
    }
    result["tbsCertificate.validity.notAfter"] = std::string(ptr, datalen);
    BIO_reset(buffer);

    // tbsCertificate.subject
    X509_NAME_print_ex(buffer, X509_get_subject_name(cert), 0, 0);
    datalen = BIO_get_mem_data(buffer, &ptr);
    if (datalen < 0 || !ptr) {
        // error
        fprintf(stderr, "BIO_get_mem_data error 2\n");
        BIO_free(buffer);
        return -1;
    }
    result["tbsCertificate.subject"] = std::string(ptr, datalen);
    BIO_reset(buffer);

    // tbsCertificate.subjectPublicKeyInfo.algorithm
    X509_PUBKEY *pubkey = X509_get_X509_PUBKEY(cert);
    X509_ALGOR *pubkeyalgo;
    const unsigned char *pubkey_bytes;
    int pubkey_length;
    X509_PUBKEY_get0_param(NULL, &pubkey_bytes, &pubkey_length, &pubkeyalgo, pubkey);
    i2a_ASN1_OBJECT(buffer, pubkeyalgo->algorithm);
    datalen = BIO_get_mem_data(buffer, &ptr);
    if (datalen < 0 || !ptr) {
        // error
        fprintf(stderr, "BIO_get_mem_data error 2\n");
        BIO_free(buffer);
        return -1;
    }
    result["tbsCertificate.subjectPublicKeyInfo.algorithm"] = std::string(ptr, datalen);
    BIO_reset(buffer);

    // tbsCertificate.subjectPublicKeyInfo.subjectPublicKey
    result["tbsCertificate.subjectPublicKeyInfo.subjectPublicKey"] = hexdump(pubkey_bytes, pubkey_length); // DER-encoded public key

    // tbsCertificate.issuerUniqueID
    // tbsCertificate.subjectUniqueID
    const ASN1_BIT_STRING *issuer_uid = NULL;
    const ASN1_BIT_STRING *subject_uid = NULL;
    X509_get0_uids(cert, &issuer_uid, &subject_uid);
    if (issuer_uid) {
        result["tbsCertificate.issuerUniqueID"] = hexdump(issuer_uid->data, issuer_uid->length);
    }
    if (subject_uid) {
        result["tbsCertificate.subjectUniqueID"] = hexdump(subject_uid->data, subject_uid->length);
    }
#if 0
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
#endif

    // signatureAlgorithm
    // signatureValue
    const X509_ALGOR *signature_algo;
    const ASN1_BIT_STRING *signature;
    X509_get0_signature(&signature, &signature_algo, cert);
    // TODO: use a different label for the 2 signaturealgorithm
    // TODO: print signatureAlgorithm.parameters
    i2a_ASN1_OBJECT(buffer, signature_algo->algorithm);
    datalen = BIO_get_mem_data(buffer, &ptr);
    if (datalen < 0 || !ptr) {
        // error
        fprintf(stderr, "BIO_get_mem_data error 2\n");
        BIO_free(buffer);
        return -1;
    }
    result["signatureAlgorithm"] = std::string(ptr, datalen);
    BIO_reset(buffer);

    result["signatureValue"] = hexdump(signature->data, signature->length);

    BIO_free(buffer);
    return 0;
}

std::map<std::string, std::string> parse_x509_der(const std::string &der_bytes)
{
    std::map<std::string, std::string> result;
    // Put the DER bytes in a BIO memory buffer
    BIO *bio = BIO_new(BIO_s_mem());
    BIO_write(bio, der_bytes.data(), der_bytes.size());
    X509 *cert = d2i_X509_bio(bio, NULL);
    if (cert) {
        populate_map(cert, result);
        X509_free(cert);
    }
    BIO_free(bio);
    return result;
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
