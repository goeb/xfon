#include <assert.h>
#include <climits>
#include <openssl/asn1.h>
#include <openssl/types.h>
#include <openssl/x509.h>
#include <string>

#include "der_decode_x509.h"
#include "util.h"

/** TODO not used. To be removed
 * @brief Get the length of an DER-encoded ASN.1 type
 * @param der_data
 * @param der_length
 * @return
 */
static int der_decode_data_size(OctetString &der_bytes)
{
    if (der_bytes.empty()) {
        fprintf(stderr, "der_decode_data_length error: empty\n");
        return -1;
    }
    if (der_bytes.size() < 2) {
        fprintf(stderr, "der_decode_data_length error: missing first byte\n");
        return -1;
    }
    int size = 0;
    if (der_bytes[0] & 0x80) {
        // Length encoded on multibytes, big-endian
        size_t n_bytes = (unsigned char)der_bytes[0] & 0x7f;
        if (n_bytes+1 > der_bytes.size()) {
            fprintf(stderr, "der_decode_data_length error: too short\n");
            return -1;
        }

        for (size_t i=1; i<n_bytes+1; i++) {
            if (size > (INT_MAX >> 8 )) {
                // unsigned integer overflow
                fprintf(stderr, "der_decode_data_length error: overflow\n");
                return -1;
            }
            size = (size << 8) + der_bytes[i];
        }
        der_bytes.erase(0, 1+n_bytes);
    } else {
        // length encoded on a single byte
        size = der_bytes[0];
        der_bytes.erase(0, 1);
    }
    return size;
}

/**
 * @brief Decode a DER ASN1 INTEGER value
 * @param der_bytes Input buffer
 * @param i_start   Index of the start of the DER-encoded value.
 *                  Will be moved forward on success.
 * @param i_end     Index 1 byte past the end of the allowed bytes
 * @param out       Returned value, allocated by the callee. Must be freed by the caller.
 * @return
 *     0 sucess
 *    -1 error. i_start is not moved, out is not allocated.
 */

static int der_decode_integer(const OctetString &der_bytes, size_t &i_start, size_t i_end, Value **out)
{
    assert(i_start < i_end);
    assert(i_end <= der_bytes.size());
    std::string integer_string;
    const unsigned char *ptr = der_bytes.data()+i_start;
    ASN1_INTEGER *integer = d2i_ASN1_INTEGER(NULL, &ptr, i_end - i_start);
    if (!integer) {
        fprintf(stderr, "der_decode_integer error\n");
        return -1;
    }
    if (integer->type == V_ASN1_NEG_INTEGER) integer_string = "-";
    integer_string += "0x"; // base 16
    integer_string += hexlify(integer->data, integer->length);
    ASN1_INTEGER_free(integer);
    i_start = ptr - der_bytes.data(); // move the index forward to consume the bytes
    *out = new Number(integer_string);
    return 0;
}

/**
 * @brief Decode a DER ASN1 BOOLEAN value
 * @param der_bytes Input buffer
 * @param i_start   Index of the start of the DER-encoded value.
 *                  Will be moved forward on success.
 * @param i_end     Index 1 byte past the end of the allowed bytes
 * @param out       Returned value, allocated by the callee. Must be freed by the caller.
 * @return
 *     0 sucess
 *    -1 error. i_start is not moved, out is not allocated.
 */
static int der_decode_boolean(const OctetString &der_bytes, size_t &i_start, size_t i_end, Value **out)
{
    assert(i_start < i_end);
    assert(i_end <= der_bytes.size());
    *out = NULL;
    if (i_end - i_start < 3) {
        fprintf(stderr, "der_decode_boolean error: size too short %lu\n", der_bytes.size());
        return -1;
    }
    if (der_bytes[i_start] != 0x01) {
        fprintf(stderr, "der_decode_boolean error: invalid tag 0x%X\n", der_bytes[i_start]);
        return -1;
    }
    if (der_bytes[i_start+1] != 0x01) {
        fprintf(stderr, "der_decode_boolean error: invalid size 0x%X\n", der_bytes[i_start+1]);
        return -1;
    }

    if (der_bytes[i_start+2]) *out = new Literal("true");
    else *out = new Literal("false");

    i_start += 3; // push the index further to consume the bytes
    return 0;
}

/**
 * @brief Decode a DER ASN1 OCTET STRING value
 * @param der_bytes
 * @param i_start   Index of the start of the DER-encoded value.
 *                  Will be moved forward on success.
 * @param i_end     Index 1 byte past the end of the allowed bytes
 * @param out       Returned value, allocated by the callee. Must be freed by the caller.
 * @return
 */
static int der_decode_octet_string(const OctetString &der_bytes, size_t &i_start, size_t i_end, Value **out)
{
    //fprintf(stderr, "debug: der_decode_octet_string\n");
    assert(i_start < i_end);
    assert(i_end <= der_bytes.size());
    const unsigned char *ptr = der_bytes.data()+i_start;
    ASN1_INTEGER *octetstring = d2i_ASN1_OCTET_STRING(NULL, &ptr, i_end - i_start);
    if (!octetstring) {
        fprintf(stderr, "der_decode_octet_string error\n");
        return -1;
    }
    i_start = ptr - der_bytes.data(); // move the index forward to consume the bytes
    *out = new String(hexlify(octetstring->data, octetstring->length));
    //fprintf(stderr, "debug: der_decode_octet_string: *out=%p\n", *out);
    ASN1_OCTET_STRING_free(octetstring);
    return 0;
}

/**
 * @brief Get DER tag, length and value
 * @param[in] der_bytes
 * @param[out] tag
 * @param[out] length
 * @param[out] value
 * @return number of bytes read, or -1 on error
 */
static int get_tag_length_value(const OctetString &der_bytes, int &tag, size_t &length, OctetString &value)
{
    long len_value;
    int xclass;
    const unsigned char *ptr = der_bytes.data();
    // Get ASN1 tag (without class) and size of the object
    int ret = ASN1_get_object(&ptr, &len_value, &tag, &xclass, der_bytes.size());
    if (ret & 0x80) return -1;
    if (len_value < 0) return -1;
    size_t len_header = ptr - der_bytes.data();
    if (len_value + len_header > der_bytes.size()) return -1;
    length = len_value;
    value = OctetString(der_bytes.data() + len_header, length);
    return len_header + value.size();
}

/* Decode BasicConstraints (DER-encoded)
 *
 * BasicConstraints ::= SEQUENCE {
 *      cA                      BOOLEAN DEFAULT FALSE,
 *      pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
 */
int der_decode_x509_basic_constraints(const OctetString &der_bytes, size_t &i_start, size_t i_end, Value **out)
{
    assert(i_start < i_end);
    assert(i_end <= der_bytes.size());

    //printf("debug: der_decode_x509_basic_constraints: der_bytes=%s\n", hexlify(der_bytes).c_str());

    size_t length;
    int tag;
    OctetString fields;
    int n_bytes = get_tag_length_value(der_bytes, tag, length, fields);
    if (n_bytes < 0) {
        fprintf(stderr, "der_decode_x509_basic_constraints: cannot decode tag and length\n");
        return -1;
    }
    if (tag != V_ASN1_SEQUENCE) {
        fprintf(stderr, "der_decode_x509_basic_constraints: not a sequence. tag=0x%X\n", tag);
        return -1;
    }
    // Possible cases here:
    // - no cA, no pathLenConstraint
    // - cA present , no pathLenConstraint
    // - no cA, pathLenConstraint present
    // - both are present

    Value *ca = NULL;
    Value *pathlenconstraint = NULL;

    if (fields.empty()) {
        // no cA, no pathLenConstraint
        ca = new Literal("false");
    } else {
        size_t i_next = 0;
        if (fields[0] == V_ASN1_BOOLEAN) {
            if (der_decode_boolean(fields, i_next, 3, &ca)) return -1;
        } else {
            // cA not present. Use the default value
            ca = new Literal("false");
        }
        // Now decode pathLenConstraint
        if (i_next >= fields.size()) {
            // no pathLenConstraint
        } else {
            if (der_decode_integer(der_bytes, i_next, i_end, &pathlenconstraint)) {
                if (ca) delete ca;
                return -1;
            }
        }
    }

    Object *obj = new Object();
    obj->insert("ca", ca);
    if (pathlenconstraint) obj->insert("pathlenconstraint", pathlenconstraint);
    *out = obj;
    return 0;
}

/**
 * @brief der_decode_x509_subject_key_identifier
 * @param der_bytes
 * @param i_start
 * @param i_end
 * @param out
 * @return 0 success, -1 error
 *
 * SubjectKeyIdentifier ::= KeyIdentifier
 * KeyIdentifier ::= OCTET STRING
 */
int der_decode_x509_subject_key_identifier(const OctetString &der_bytes, size_t &i_start, size_t i_end, Value **out)
{
    return der_decode_octet_string(der_bytes, i_start, i_end, out);
}

std::string get_bio_mem_string(BIO *buffer)
{
    char *ptr;
    long datalen = BIO_get_mem_data(buffer, &ptr);
    if (datalen < 0 || !ptr) {
        fprintf(stderr, "BIO_get_mem_data error\n");
        return "";
    }
    return std::string(ptr, datalen);
}

static int der_decode_x509_name(const OctetString &der_bytes, Value **out)
{
    int ret = 0;
    *out = NULL;
    const unsigned char *ptr = der_bytes.data();
    X509_NAME *name = d2i_X509_NAME(NULL, &ptr, der_bytes.size());
    if (!name) {
        fprintf(stderr, "der_decode_x509_name: error while parsing %s\n", hexlify(der_bytes).c_str());
        return -1;
    }
    BIO *buffer = BIO_new(BIO_s_mem());
    int err = X509_NAME_print_ex(buffer, name, 0, 0);
    if (err < 0) {
        fprintf(stderr, "der_decode_x509_name: error while converting %s\n", hexlify(der_bytes).c_str());
        ret = -1;
    } else *out = new String(get_bio_mem_string(buffer));

    X509_NAME_free(name);
    return ret;
}

/**
 * @brief der_decode_x509_general_names
 * @param der_bytes
 * @param out
 * @return
 *
 * GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
 *
 * GeneralName ::= CHOICE {
 *      otherName                 [0]  AnotherName,
 *      rfc822Name                [1]  IA5String,
 *      dNSName                   [2]  IA5String,
 *      x400Address               [3]  ORAddress,
 *      directoryName             [4]  Name,
 *      ediPartyName              [5]  EDIPartyName,
 *      uniformResourceIdentifier [6]  IA5String,
 *      iPAddress                 [7]  OCTET STRING,
 *      registeredID              [8]  OBJECT IDENTIFIER }
 */
int der_decode_x509_general_names(const OctetString &der_bytes, Value **out)
{
    //fprintf(stderr, "debug: der_decode_x509_general_names: %s\n", hexlify(der_bytes).c_str());
    size_t length;
    int tag;
    OctetString value = der_bytes;
    Object *obj = new Object();
    while (value.size()) {
        OctetString field;
        int n_bytes = get_tag_length_value(der_bytes, tag, length, field);
        if (n_bytes < 0) {
            fprintf(stderr, "der_decode_x509_authority_key_identifier: cannot decode tag and length\n");
            delete obj;
            return -1;
        }
        //fprintf(stderr, "debug: der_decode_x509_general_names: tag=%d\n", tag);

        switch (tag) {
        case 0:
            obj->insert("otherName", new String(hexlify(field)));
            break;
        case 1:
            obj->insert("rfc822Name", new String(hexlify(field)));
            break;
        case 2:
            obj->insert("dNSName", new String(hexlify(field)));
            break;
        case 3:
            obj->insert("x400Address", new String(hexlify(field)));
            break;
        case 4:
        {
            Value *name = NULL;
            int err = der_decode_x509_name(field, &name);
            if (!err) {
                //fprintf(stderr, "debug: der_decode_x509_name() -> name=%p\n", name);
                obj->insert("directoryName", name);
            }
        }
            break;
        case 5:
            obj->insert("ediPartyName", new String(hexlify(field)));
            break;
        case 6:
            obj->insert("uniformResourceIdentifier", new String(hexlify(field)));
            break;
        case 7:
            obj->insert("iPAddress", new String(hexlify(field)));
            break;
        case 8:
            obj->insert("registeredID", new String(hexlify(field)));
            break;
        default:
            fprintf(stderr, "der_decode_x509_general_names: invalid tag 0x%x\n", tag);
            delete obj;
            return -1;
        }
        value.erase(0, n_bytes);
    }
    *out = obj;
    return 0;
}

/**
 * @brief der_decode_x509_authority_key_identifier
 * @param der_bytes
 * @param out
 * @return 0 success, -1 error
 *
 * AuthorityKeyIdentifier ::= SEQUENCE {
 *   keyIdentifier             [0] KeyIdentifier            OPTIONAL,
 *   authorityCertIssuer       [1] GeneralNames             OPTIONAL,
 *   authorityCertSerialNumber [2] CertificateSerialNumber  OPTIONAL }
 *   -- authorityCertIssuer and authorityCertSerialNumber MUST both
 *   -- be present or both be absent
 *
 * Eg:
 * 3016   8014 EE5678837CBF5D942D231788D395370BE54723CC
 * 308187 8014 BF5FB7D1CEDD1F86F45B55ACDCD710C20EA988E7
 *        A16C A46A 3068 310B3009060355040613025553 3125 3023060355040A131C537461726669656C6420546563686E6F6C6F676965732C20496E632E31323030060355040B1329537461726669656C6420436C61737320322043657274696669636174696F6E20417574686F72697479
 *        8201 00
 *
 */
int der_decode_x509_authority_key_identifier(const OctetString &der_bytes, Value **out)
{
    //fprintf(stderr, "debug: der_decode_x509_authority_key_identifier: %s\n", hexlify(der_bytes).c_str());
    size_t length;
    int tag;
    OctetString value;
    int n_bytes = get_tag_length_value(der_bytes, tag, length, value);
    if (n_bytes < 0) {
        fprintf(stderr, "der_decode_x509_authority_key_identifier: cannot decode tag and length\n");
        return -1;
    }
    if (tag != V_ASN1_SEQUENCE) {
        fprintf(stderr, "der_decode_x509_authority_key_identifier: not a sequence. tag=0x%X\n", tag);
        return -1;
    }
    Object *obj = NULL;
    Value *keyidentifier = NULL;
    Value *authoritycertissuer = NULL;
    Value *authoritycertserialnumber = NULL;

    if (length == 0) {
        // null parameter
    } else {
        while (value.size()) {
            //fprintf(stderr, "debug: der_decode_x509_authority_key_identifier: value=%s\n", hexlify(value).c_str());
            OctetString field;
            int n_bytes = get_tag_length_value(value, tag, length, field);
            if (n_bytes < 0) {
                fprintf(stderr, "der_decode_x509_authority_key_identifier: cannot decode tag and length (2)\n");
                return -1;
            }
            //printf("debug: der_decode_x509_authority_key_identifier: tag=%d\n", tag);
            if (0 == tag) {
                keyidentifier = new String(hexlify(field));
            } else if (1 == tag) {
                der_decode_x509_general_names(field, &authoritycertissuer);
            } else if (2 == tag) {
                // rebuild a full ASN1 DER INTEGER with universal tag and length
                OctetString der_integer = value;
                der_integer[0] = 0x2; // set a universal tag for INTEGER
                size_t i=0;
                if (der_decode_integer(der_integer, i, der_integer.size(), &authoritycertserialnumber)) {
                    goto error;
                }
            } else {
                fprintf(stderr, "der_decode_x509_authority_key_identifier: invalid tag %d\n", tag);
                return -1;
            }
            // Remove the consumed bytes
            value.erase(0, n_bytes);
        }
    }

    obj = new Object();
    if (keyidentifier) obj->insert("keyidentifier", keyidentifier);
    if (authoritycertissuer) obj->insert("authoritycertissuer", authoritycertissuer);
    if (authoritycertserialnumber) obj->insert("authoritycertserialnumber", authoritycertserialnumber);
    *out = obj;
    return 0;

error:
    if (keyidentifier) delete keyidentifier;
    if (authoritycertissuer) delete authoritycertissuer;
    if (authoritycertserialnumber) delete authoritycertserialnumber;
    return -1;
}

int der_decode_x509_key_usage(const OctetString &der_bytes, size_t &i_start, size_t i_end, Value **out)
{
    assert(i_start < i_end);
    assert(i_end <= der_bytes.size());

    const unsigned char *ptr = der_bytes.data() + i_start;
    long len;
    int tag, xclass;
    // Get ASN1 tag (without class) and size of the object
    int ret = ASN1_get_object(&ptr, &len, &tag, &xclass, i_end - i_start);
    if (ret & 0x80) {
        fprintf(stderr, "der_decode_x509_key_usage: cannot decode tag and length\n");
        return -1;
    }
    if (tag != V_ASN1_BIT_STRING) {
        fprintf(stderr, "der_decode_x509_key_usage: not a BIT STRING. tag=0x%X, class=0x%X\n", tag, xclass);
        return -1;
    }

    *out = new String(hexlify(ptr, len));
    return 0;
}
