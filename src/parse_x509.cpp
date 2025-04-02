
/* Parse x509 implementation using openssl (libcrypto)
 */

#include <assert.h>
#include <openssl/asn1.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "parse_x509.h"


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

OctetString base64_decode(const std::string &base64lines)
{
    BIO *bio = BIO_new(BIO_s_mem());
    BIO_write(bio, base64lines.data(), base64lines.size());
    BIO *b64_bio = BIO_new(BIO_f_base64());
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL); // Don't require newlines
    BIO_push(b64_bio, bio);
    unsigned char one_byte;
    OctetString result;
    while (0 < BIO_read(b64_bio, &one_byte, 1)) { // Read byte-by-byte
        result += one_byte;
    } // Once we're done reading decoded data, BIO_read returns -1 even though there's no error

    BIO_free_all(b64_bio); // free all BIO in chain
    return result;
}
