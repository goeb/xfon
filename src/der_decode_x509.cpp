#include <assert.h>
#include <climits>
#include <openssl/asn1.h>
#include <openssl/types.h>
#include <openssl/x509.h>
#include <string>
#include <sstream>
#include <vector>

#include "certificate.h"
#include "der_decode_x509.h"
#include "oid_name.h"
#include "util.h"

//#define DEBUG

#define ERROR(...) do { fprintf(stderr, "%s: ", __func__); \
                            fprintf(stderr, __VA_ARGS__); \
                            fprintf(stderr, "\n"); } while (0)
#ifdef DEBUG
#define DEBUG_DUMP(_msg, _bytes, _limit) do { fprintf(stderr, "%s: %s: ", __func__, _msg); \
                                              fprintf(stderr, hexlify(_bytes, _limit).c_str()); \
                                              fprintf(stderr, "\n"); } while (0)
#else
#define DEBUG_DUMP(_msg, _bytes, _limit)
#endif
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
    DEBUG_DUMP("", der_bytes, 16);
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

static int der_decode_header(const OctetString &der_bytes, int expected_tag, OctetString &value)
{
    DEBUG_DUMP("", der_bytes, 16);
    size_t length;
    int tag;
    OctetString data;
    int n_bytes = get_tag_length_value(der_bytes, tag, length, data);
    if (n_bytes <= 0) {
        ERROR("cannot decode tag and length");
        return -1;
    }
    if (tag != expected_tag) {
        ERROR("Unexpected tag 0x%X (expected was 0x%X)", tag, expected_tag);
        return -1;
    }
    value = data;
    return n_bytes;
}


/** TODO not used. To be removed
 * @brief Get the length of an DER-encoded ASN.1 type
 * @param der_data
 * @param der_length
 * @return
 */
static int der_decode_data_size(OctetString &der_bytes)
{
    if (der_bytes.empty()) {
        ERROR("empty");
        return -1;
    }
    if (der_bytes.size() < 2) {
        ERROR("missing first byte");
        return -1;
    }
    int size = 0;
    if (der_bytes[0] & 0x80) {
        // Length encoded on multibytes, big-endian
        size_t n_bytes = (unsigned char)der_bytes[0] & 0x7f;
        if (n_bytes+1 > der_bytes.size()) {
            ERROR("too short");
            return -1;
        }

        for (size_t i=1; i<n_bytes+1; i++) {
            if (size > (INT_MAX >> 8 )) {
                // unsigned integer overflow
                ERROR("error: overflow");
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
        ERROR("error");
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
 * @brief der_decode_integer
 * @param der_bytes
 * @param value
 * @return
 *     -1 error
 *     >0 number of decoded bytes
 */
static int der_decode_integer(const OctetString &der_bytes, Integer &value)
{
    DEBUG_DUMP("", der_bytes, 16);
    size_t length;
    int tag;
    OctetString data;
    int n_bytes = get_tag_length_value(der_bytes, tag, length, data);
    if (n_bytes < 0) {
        ERROR("cannot decode tag and length");
        return -1;
    }
    if (tag != V_ASN1_INTEGER) {
        ERROR("not an integer. tag=0x%X", tag);
        return -1;
    }

    if (data.empty()) {
        ERROR("empty integer");
        return -1;
    }

    value = "";
    // Get the sign +/-
    if (data[0] & 0x80) {
        value += "-";
        // flip all bits and add 1
        size_t len = data.size();
        for (size_t i=0; i<len; i++) data[i] = 0xff - data[i]; // flip bits
        // add 1 and propagate the carry
        int carry = 1;
        for (int i=len-1; i>=0; i--) {
            data[i] += carry;
            if (data[i] == 0x00) carry = 1;
            else break; // no more carry
        }
    }
    value += "0x"; // base 16
    value += hexlify(data.data(), data.size());

    return n_bytes;
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
        ERROR("error: size too short %lu", der_bytes.size());
        return -1;
    }
    if (der_bytes[i_start] != 0x01) {
        ERROR("error: invalid tag 0x%X", der_bytes[i_start]);
        return -1;
    }
    if (der_bytes[i_start+1] != 0x01) {
        ERROR("error: invalid size 0x%X", der_bytes[i_start+1]);
        return -1;
    }

    if (der_bytes[i_start+2]) *out = new Literal("true");
    else *out = new Literal("false");

    i_start += 3; // push the index further to consume the bytes
    return 0;
}

static int der_decode_boolean(const OctetString &der_bytes, bool &boolean)
{
    DEBUG_DUMP("", der_bytes, 16);
    OctetString value;
    int n_bytes = der_decode_header(der_bytes, V_ASN1_BOOLEAN, value);
    if (n_bytes < 0) {
        ERROR("Cannot decode header");
        return -1;
    }

    if (value.size() != 1) {
        ERROR("Invalid payload (size %lu)", value.size());
        return -1;
    }
    if (value[0]) boolean = true;
    else boolean = false;

    return n_bytes;
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
        ERROR("error");
        return -1;
    }
    i_start = ptr - der_bytes.data(); // move the index forward to consume the bytes
    *out = new String(hexlify(octetstring->data, octetstring->length));
    //fprintf(stderr, "debug: der_decode_octet_string: *out=%p\n", *out);
    ASN1_OCTET_STRING_free(octetstring);
    return 0;
}

/**
 * @brief Decode a DER ASN1 OCTET STRING value
 * @param der_bytes
 * @param octetstring
 * @return
 *     -1 error
 *     >0 number of bytes consumed
 */
static int der_decode_octet_string(const OctetString &der_bytes, OctetString &data)
{
    DEBUG_DUMP("", der_bytes, 16);
    OctetString value;
    int n_bytes = der_decode_header(der_bytes, V_ASN1_OCTET_STRING, value);
    if (n_bytes < 0) {
        ERROR("Cannot decode header");
        return -1;
    }
    data = value;
    return n_bytes;
}

static int der_decode_bit_string(const OctetString &der_bytes, OctetString &data)
{
    DEBUG_DUMP("", der_bytes, 16);
    OctetString value;
    int n_bytes = der_decode_header(der_bytes, V_ASN1_BIT_STRING, value);
    if (n_bytes < 0) {
        ERROR("Cannot decode header");
        return -1;
    }
    data = value;
    return n_bytes;
}

static int der_decode_bit_string(const OctetString &der_bytes, std::vector<bool> &bits)
{
    DEBUG_DUMP("", der_bytes, 16);

    OctetString value;
    int n_bytes_total = der_decode_header(der_bytes, V_ASN1_BIT_STRING, value);
    if (n_bytes_total < 0) {
        ERROR("Cannot decode header");
        return -1;
    }

    size_t size = value.size();

    if (!size) {
        ERROR("Empty value");
        return -1;
    }

    unsigned int unused_bits = value[0];
    for (size_t i=1; i<size; i++) {
        unsigned char byte = value[i];
        // get the bits of this byte
        for (size_t j=0; j<8-unused_bits; j++) {
            bool bit = (byte >> (8-j-1)) & 0x1;
            bits.insert(bits.end(), bit);
        }
    }

    return n_bytes_total;
}

int der_decode_object_identifier(const OctetString &der_bytes, ObjectIdentifier &oid)
{
    DEBUG_DUMP("", der_bytes, 16);
    OctetString value;
    int n_bytes = der_decode_header(der_bytes, V_ASN1_OBJECT, value);
    if (n_bytes < 0 || value.empty()) {
        ERROR("Cannot decode header");
        return -1;
    }

    std::ostringstream result;
    // First byte contains 2 values
    result << value[0] / 40 << "." << value[0] % 40;

    // Following bytes
    size_t len = value.size();
    unsigned int current = 0;
    for (size_t i=1; i<len; i++) {
        if (value[i] & 0x80) {
            // multi-byte series
            current += value[i] & 0x7f;
            if (UINT_MAX >> 3 < current) {
                ERROR("Integer overflow");
                return -1;
            }
            current = current << 3;
        } else {
            current += value[i];
            result << "." << current;
            current = 0;
        }
    }
    oid = result.str();
    return n_bytes;
}

/**
 * @brief der_decode_x509_algorithm_identifier
 * @param der_bytes
 * @param algoid
 * @return
 *
 * AlgorithmIdentifier  ::=  SEQUENCE  {
 *       algorithm               OBJECT IDENTIFIER,
 *       parameters              ANY DEFINED BY algorithm OPTIONAL  }
 *                                  -- contains a value of the type
 *                                  -- registered for use with the
 *                                  -- algorithm object identifier value
 */
static int der_decode_x509_algorithm_identifier(const OctetString &der_bytes, AlgorithmIdentifier &algoid)
{
    DEBUG_DUMP("", der_bytes, 16);
    OctetString value;
    int n_bytes = der_decode_header(der_bytes, V_ASN1_SEQUENCE, value);
    if (n_bytes < 0) {
        ERROR("Cannot decode header");
        return -1;
    }
    int n_bytes_algorithm = der_decode_object_identifier(value, algoid.algorithm);
    if (n_bytes_algorithm < 0) {
        ERROR("Cannot decode algorithm");
        return -1;
    }

    value.erase(0, n_bytes_algorithm);

    algoid.parameters = value;

    return n_bytes;
}

/**
 * @brief der_decode_x509_attribute_value
 * @param der_bytes
 * @param attribute
 * @return
 *
 * AttributeTypeAndValue   ::= SEQUENCE {
 *         type    AttributeType,
 *         value   AttributeValue }
 */
static int der_decode_x509_attribute_value(const OctetString &der_bytes, AttributeTypeAndValue &attribute)
{
    OctetString sequence;
    int n_bytes_total = der_decode_header(der_bytes, V_ASN1_SEQUENCE, sequence);
    if (n_bytes_total < 0) {
        ERROR("Cannot decode header");
        return -1;
    }

    ObjectIdentifier oid;
    int n_bytes = der_decode_object_identifier(sequence, oid);
    if (n_bytes < 0) {
        ERROR("Cannot decode OID");
        return -1;
    }
    sequence.erase(0, n_bytes);

    // The value can be of different types: PrintableString, UTF8String, etc.
    size_t length;
    int tag;
    OctetString value;
    n_bytes = get_tag_length_value(sequence, tag, length, value);
    if (n_bytes <= 0) {
        ERROR("cannot decode tag and length");
        return -1;
    }

    switch (tag) {
    case V_ASN1_UTF8STRING:
    case V_ASN1_NUMERICSTRING:
    case V_ASN1_PRINTABLESTRING:
    case V_ASN1_T61STRING:
    case V_ASN1_IA5STRING:
    case V_ASN1_VISIBLESTRING:
        attribute.value = std::string((char *)value.data(), value.size());
        break;
    default:
        fprintf(stderr, "der_decode_object_identifier: unsupported value with tag=0x%X\n", tag);
        attribute.value = "[der]";
        attribute.value += hexlify(sequence);
    }

    attribute.type = oid;

    return n_bytes_total;
}

/**
 * @brief der_decode_x509_name
 * @param der_bytes
 * @param name
 * @return
 *
 * Name ::= CHOICE { -- only one possibility for now --
 *       rdnSequence  RDNSequence }
 *
 * RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
 *
 * RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
 */
static int der_decode_x509_name(const OctetString &der_bytes, Name &name)
{
    DEBUG_DUMP("", der_bytes, 32);

    // decode SEQUENCE OF header
    OctetString sequenceof;
    int n_bytes_total = der_decode_header(der_bytes, V_ASN1_SEQUENCE, sequenceof);
    if (n_bytes_total < 0) {
        ERROR("Cannot decode header");
        return -1;
    }

    // while more in the SEQUENCE OF, decode SET OF
    while (sequenceof.size()) {
        OctetString setof;
        int n_bytes_setof = der_decode_header(sequenceof, V_ASN1_SET, setof);
        if (n_bytes_setof < 0) {
            ERROR("Cannot decode header (SET OF)");
            return -1;
        }
        // while more in each SET OF, decode AttributeTypeAndValue
        std::set<AttributeTypeAndValue> attributes;
        while (setof.size()) {
            AttributeTypeAndValue attribute;
            int n_bytes = der_decode_x509_attribute_value(setof, attribute);
            if (n_bytes < 0) {
                ERROR("Cannot decode attribute value");
                return -1;
            }
            attributes.insert(attribute);
            setof.erase(0, n_bytes);
        }

        name.push_back(attributes);
        sequenceof.erase(0, n_bytes_setof);
    }

    return n_bytes_total;
}

/**
 * @brief Convert a GeneralizedTime payload to a YYYY-MM-dd hh:mm:ss... format
 */
static std::string generalized_time_to_string(const std::string &der_time)
{
    std::string result;
    // Expect YYYYMMDDhhmmss[.f...]Z
    if (result.size() < 14) {
        // Unexpected. Do not parse
        result = der_time;
    } else {
        result = der_time.substr(0, 4) + "-";
        result += der_time.substr(4, 2) + "-";
        result += der_time.substr(6, 2) + " ";
        result += der_time.substr(8, 2) + ":";
        result += der_time.substr(10, 2) + ":";
        result += der_time.substr(12, std::string::npos);
    }
    return result;
}

static int der_decode_generalized_time(const OctetString &der_bytes, std::string &time)
{
    OctetString value;
    int n_bytes_total = der_decode_header(der_bytes, V_ASN1_GENERALIZEDTIME, value);
    if (n_bytes_total < 0) {
        ERROR("Cannot decode header");
        return -1;
    }
    time = generalized_time_to_string(std::string((char*)value.data(), value.size()));
    return n_bytes_total;
}

/*
 * Time ::= CHOICE {
 *      utcTime        UTCTime,
 *      generalTime    GeneralizedTime }
 *
 * UTCTime not supported as year is on 2 digits only.
 * Expected formats:
 * - YYYYMMDDhhmmss[.fff...]
 * - 19920521000000.123Z
 */
static int der_decode_x509_time(const OctetString &der_bytes, std::string &time)
{
    DEBUG_DUMP("", der_bytes, 64);

    size_t length;
    int tag;
    OctetString value;
    int n_bytes = get_tag_length_value(der_bytes, tag, length, value);
    if (n_bytes < 0) {
        ERROR("cannot decode tag and length");
        return -1;
    }

    std::string timetmp = std::string((char*)value.data(), value.size());
    switch (tag) {
    case V_ASN1_UTCTIME:
        // Expect YYMMDDhhmmssZ
        // Add "20" (for 21st century) at the beginning to complete the year on 4 digits
        timetmp.insert(0, "20");
    case V_ASN1_GENERALIZEDTIME:
        time = generalized_time_to_string(timetmp);
        break;
    default:
        ERROR("cannot decode time");
        return -1;
    }

    return n_bytes;
}

/*
 * Validity ::= SEQUENCE {
 *    notBefore      Time,
 *    notAfter       Time  }
 */
static int der_decode_x509_validity(const OctetString &der_bytes, Validity &validity)
{
    OctetString value;
    int n_bytes_total = der_decode_header(der_bytes, V_ASN1_SEQUENCE, value);
    if (n_bytes_total < 0) {
        ERROR("Cannot decode header");
        return -1;
    }

    std::string not_before;
    int n_bytes = der_decode_x509_time(value, not_before);
    if (n_bytes < 0) {
        ERROR("Cannot decode notBbefore");
        return -1;
    }
    value.erase(0, n_bytes);
    std::string not_after;
    n_bytes = der_decode_x509_time(value, not_after);
    if (n_bytes < 0) {
        ERROR("Cannot decode notBbefore");
        return -1;
    }

    validity.not_after = not_after;
    validity.not_before = not_before;

    return n_bytes_total;
}

static int der_decode_x509_subject_public_key_info(const OctetString &der_bytes, SubjectPublicKeyInfo &spki)
{
    OctetString value;
    int n_bytes_total = der_decode_header(der_bytes, V_ASN1_SEQUENCE, value);
    if (n_bytes_total < 0) {
        ERROR("Cannot decode header");
        return -1;
    }


    int n_bytes = der_decode_x509_algorithm_identifier(value, spki.algorithm);
    if (n_bytes < 0) {
        ERROR("Cannot decode algorithm");
        return -1;
    }

    value.erase(0, n_bytes);

    n_bytes = der_decode_bit_string(value, spki.subject_public_key);
    if (n_bytes < 0) {
        ERROR("cannot decode bit string");
        return -1;
    }

    return n_bytes_total;
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
        ERROR("cannot decode tag and length");
        return -1;
    }
    if (tag != V_ASN1_SEQUENCE) {
        ERROR("not a sequence. tag=0x%X", tag);
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

static int der_decode_x509_basic_constraints(const OctetString &der_bytes, BasicConstraints &basic_constraints)
{
    DEBUG_DUMP("", der_bytes, 16);

    OctetString sequence;
    int n_bytes_total = der_decode_header(der_bytes, V_ASN1_SEQUENCE, sequence);
    if (n_bytes_total < 0) {
        ERROR("Cannot decode header");
        return -1;
    }

    if (!sequence.empty() && sequence[0] == V_ASN1_BOOLEAN) {
        // This is 'ca'
        int n_bytes = der_decode_boolean(sequence, basic_constraints.ca);
        if (n_bytes < 0) {
            ERROR("Cannot decode boolean");
            return -1;
        }
        sequence.erase(0, n_bytes);
    } else {
        // default value FALSE
        basic_constraints.ca = false;
    }

    if (!sequence.empty()) {
        int n_bytes = der_decode_integer(sequence, basic_constraints.path_len_constraint);
        if (n_bytes < 0) {
            ERROR("Cannot decode integer");
            return -1;
        }
    }
    return n_bytes_total;
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
        ERROR("BIO_get_mem_data error");
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
        ERROR("error while parsing %s", hexlify(der_bytes).c_str());
        return -1;
    }
    BIO *buffer = BIO_new(BIO_s_mem());
    int err = X509_NAME_print_ex(buffer, name, 0, 0);
    if (err < 0) {
        ERROR("error while converting %s", hexlify(der_bytes).c_str());
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
            ERROR("cannot decode tag and length");
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
            ERROR("invalid tag 0x%x", tag);
            delete obj;
            return -1;
        }
        value.erase(0, n_bytes);
    }
    *out = obj;
    return 0;
}

static int der_decode_x509_general_names(const OctetString &der_bytes, OctetString &value)
{
    // TODO log that this is not decoded
    value = der_bytes;
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
    size_t length;
    int tag;
    OctetString value;
    int n_bytes = get_tag_length_value(der_bytes, tag, length, value);
    if (n_bytes < 0) {
        ERROR("cannot decode tag and length");
        return -1;
    }
    if (tag != V_ASN1_SEQUENCE) {
        ERROR("not a sequence. tag=0x%X", tag);
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
                ERROR("cannot decode tag and length (2)");
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
                ERROR("invalid tag %d", tag);
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

/**
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
static int der_decode_x509_authority_key_identifier(const OctetString &der_bytes, AuthorityKeyIdentifier &akid)
{
    // Set empty values for optional fields
    akid.key_identifier = OctetString();
    akid.authority_cert_issuer = OctetString();
    akid.authority_cert_serial_number = "";

    OctetString sequence;
    int n_bytes_total = der_decode_header(der_bytes, V_ASN1_SEQUENCE, sequence);
    if (n_bytes_total < 0) {
        ERROR("Cannot decode header");
        return -1;
    }

    while (sequence.size()) {
        size_t length;
        int tag;
        OctetString field;
        int n_bytes_field = get_tag_length_value(sequence, tag, length, field);
        if (n_bytes_field <= 0) {
            ERROR("cannot decode tag and length");
            return -1;
        }
        if (0 == tag) {
            akid.key_identifier = field;
        } else if (1 == tag) {
            der_decode_x509_general_names(field, akid.authority_cert_issuer);
        } else if (2 == tag) {
            // rebuild a full ASN1 DER INTEGER with universal tag and length
            OctetString der_integer = field;
            der_integer[0] = 0x2; // set a universal tag for INTEGER
            size_t i=0;
            int n_bytes_integer = der_decode_integer(der_integer, akid.authority_cert_serial_number);
            if (n_bytes_integer < 0) {
                ERROR("cannot decode integer");
                return -1;
            }
        } else {
            ERROR("invalid tag %d", tag);
            return -1;
        }
        // Remove the consumed bytes
        sequence.erase(0, n_bytes_field);
    }
    return n_bytes_total;
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
        ERROR("cannot decode tag and length");
        return -1;
    }
    if (tag != V_ASN1_BIT_STRING) {
        ERROR("not a BIT STRING. tag=0x%X, class=0x%X", tag, xclass);
        return -1;
    }

    *out = new String(hexlify(ptr, len));
    return 0;
}

/*
 * KeyUsage ::= BIT STRING {
 *      digitalSignature        (0),
 *      nonRepudiation          (1),  -- recent editions of X.509 have
 *                                 -- renamed this bit to contentCommitment
 *      keyEncipherment         (2),
 *      dataEncipherment        (3),
 *      keyAgreement            (4),
 *      keyCertSign             (5),
 *      cRLSign                 (6),
 *      encipherOnly            (7),
 *      decipherOnly            (8) }
 */
static int der_decode_x509_key_usage(const OctetString &der_bytes, KeyUsage &key_usage)
{
    DEBUG_DUMP("", der_bytes, 16);

    std::vector<bool> bits;
    int n_bytes = der_decode_bit_string(der_bytes, bits);
    if (n_bytes < 0) {
        ERROR("Cannot decode bit string");
        return -1;
    }

    if (bits.size() > 9) {
        ERROR("Bit string too long: %lu", bits.size());
        return -1;
    }

    // pad with zeros to be sure to have 9 bits
    bits.insert(bits.end(), 9 - bits.size(), 0);

    if (bits[0]) key_usage.insert("digitalSignature");
    if (bits[1]) key_usage.insert("nonRepudiation");
    if (bits[2]) key_usage.insert("keyEncipherment");
    if (bits[3]) key_usage.insert("dataEncipherment");
    if (bits[4]) key_usage.insert("keyAgreement");
    if (bits[5]) key_usage.insert("keyCertSign");
    if (bits[6]) key_usage.insert("cRLSign");
    if (bits[7]) key_usage.insert("encipherOnly");
    if (bits[8]) key_usage.insert("decipherOnly");

    return n_bytes;
}


/*
 * Extension  ::=  SEQUENCE  {
 *     extnID      OBJECT IDENTIFIER,
 *     critical    BOOLEAN DEFAULT FALSE,
 *     extnValue   OCTET STRING
 *                 -- contains the DER encoding of an ASN.1 value
 *                 -- corresponding to the extension type identified
 *                 -- by extnID
 *     }
 */
static int der_decode_x509_extension(const OctetString &der_bytes, Extension &extension)
{
    DEBUG_DUMP("", der_bytes, 16);

    OctetString sequence;
    int n_bytes_total = der_decode_header(der_bytes, V_ASN1_SEQUENCE, sequence);
    if (n_bytes_total < 0) {
        ERROR("Cannot decode header");
        return -1;
    }

    int n_bytes = der_decode_object_identifier(sequence, extension.extn_id);
    if (n_bytes < 0) {
        ERROR("Cannot decode header");
        return -1;
    }
    sequence.erase(0, n_bytes);

    if (sequence.empty()) {
        ERROR("Missing field after extn_id");
        return -1;
    }

    if (sequence[0] == V_ASN1_BOOLEAN) {
        // This is 'critical'
        n_bytes = der_decode_boolean(sequence, extension.critical);
        if (n_bytes < 0) {
            ERROR("Cannot decode boolean");
            return -1;
        }
        sequence.erase(0, n_bytes);
    } else {
        // default value FALSE
        extension.critical = false;
    }

    OctetString extn_value;
    n_bytes = der_decode_octet_string(sequence, extn_value);
    if (n_bytes < 0) {
        ERROR("Cannot decode extnValue octet string");
        return -1;
    }

    // TODO add warnings for fields below that are not fully decoded
    std::string oid_name = oid_get_name(extension.extn_id);
    if (oid_name == "id-ce-subjectKeyIdentifier") {
        OctetString data;
        int n_bytes = der_decode_octet_string(extn_value, data);
        if (n_bytes < 0) {
            ERROR("Cannot decode id-ce-subjectKeyIdentifier");
            return -1;
        }
        extension.extn_value.emplace<SubjectKeyIdentifier>(data);
    } else if (oid_name == "id-ce-keyUsage") {
        KeyUsage key_usage;
        int n_bytes = der_decode_x509_key_usage(extn_value, key_usage);
        if (n_bytes < 0) {
            ERROR("Cannot decode id-ce-keyUsage");
            return -1;
        }
        extension.extn_value = key_usage;
    } else if (oid_name == "id-ce-privateKeyUsagePeriod") {
        extension.extn_value = extn_value;
    } else if (oid_name == "id-ce-subjectAltName") {
        OctetString value;
        der_decode_x509_general_names(extn_value, value);
        extension.extn_value = value;
    } else if (oid_name == "id-ce-issuerAltName") {
        OctetString value;
        der_decode_x509_general_names(extn_value, value);
        extension.extn_value = value;
    } else if (oid_name == "id-ce-basicConstraints") {
        BasicConstraints basic_constraints;
        int n_bytes = der_decode_x509_basic_constraints(extn_value, basic_constraints);
        if (n_bytes < 0) {
            ERROR("Cannot decode id-ce-basicConstraints");
            return -1;
        }
        extension.extn_value = basic_constraints;
    } else if (oid_name == "id-ce-cRLNumber") {
        extension.extn_value = extn_value;
    } else if (oid_name == "id-ce-cRLReasons") {
        extension.extn_value = extn_value;
    } else if (oid_name == "id-ce-instructionCode") {
        extension.extn_value = extn_value;
    } else if (oid_name == "id-ce-holdInstructionCode") {
        extension.extn_value = extn_value;
    } else if (oid_name == "id-ce-invalidityDate") {
        std::string time;
        int n_bytes = der_decode_generalized_time(extn_value, time);
        if (n_bytes < 0) {
            ERROR("Cannot decode id-ce-invalidityDate");
            return -1;
        }
        extension.extn_value = time;
    } else if (oid_name == "id-ce-issuingDistributionPoint") {
        extension.extn_value = extn_value;
    } else if (oid_name == "id-ce-deltaCRLIndicator") {
        extension.extn_value = extn_value;
    } else if (oid_name == "id-ce-issuingDistributionPoint") {
        extension.extn_value = extn_value;
    } else if (oid_name == "id-ce-certificateIssuer") {
        OctetString value;
        der_decode_x509_general_names(extn_value, value);
        extension.extn_value = value;
    } else if (oid_name == "id-ce-nameConstraints") {
        extension.extn_value = extn_value;
    } else if (oid_name == "id-ce-cRLDistributionPoints") {
        extension.extn_value = extn_value;
    } else if (oid_name == "id-ce-certificatePolicies") {
        extension.extn_value = extn_value;
    } else if (oid_name == "id-ce-policyMappings") {
        extension.extn_value = extn_value;
    } else if (oid_name == "id-ce-authorityKeyIdentifier") {
        AuthorityKeyIdentifier akid;
        int n_bytes = der_decode_x509_authority_key_identifier(extn_value, akid);
        if (n_bytes < 0) {
            ERROR("Cannot decode id-ce-authorityKeyIdentifier");
            return -1;
        }
        extension.extn_value = akid;
    } else if (oid_name == "id-ce-policyConstraints") {
        extension.extn_value = extn_value;
    } else if (oid_name == "id-ce-extKeyUsage") {
        extension.extn_value = extn_value;
    } else {
        extension.extn_value = extn_value;
    }

    return n_bytes_total;
}

/*
 * Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
 */
int der_decode_x509_extensions(const OctetString &der_bytes, Extensions &extensions)
{
    DEBUG_DUMP("", der_bytes, 16);

    // decode SEQUENCE OF header
    OctetString sequenceof;
    int n_bytes_total = der_decode_header(der_bytes, V_ASN1_SEQUENCE, sequenceof);
    if (n_bytes_total < 0) {
        ERROR("Cannot decode header");
        return -1;
    }

    // while more in the SEQUENCE OF, decode SET OF
    while (sequenceof.size()) {
        Extension extension;
        int n_bytes = der_decode_x509_extension(sequenceof, extension);
        if (n_bytes < 0) {
            ERROR("Cannot decode extension");
            return -1;
        }
        extensions.items[extension.extn_id] = extension;
        sequenceof.erase(0, n_bytes);
    }

    return n_bytes_total;
}

/**
 * @brief der_decode_x509_tbs_certificate
 * @param der_bytes
 * @param tbs_certificate
 * @return
 *
 *  TBSCertificate  ::=  SEQUENCE  {
 *       version         [0]  Version DEFAULT v1,
 *       serialNumber         CertificateSerialNumber,
 *       signature            AlgorithmIdentifier,
 *       issuer               Name,
 *       validity             Validity,
 *       subject              Name,
 *       subjectPublicKeyInfo SubjectPublicKeyInfo,
 *       issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
 *                            -- If present, version MUST be v2 or v3
 *       subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
 *                            -- If present, version MUST be v2 or v3
 *       extensions      [3]  Extensions OPTIONAL
 *                            -- If present, version MUST be v3 --  }
 */
static int der_decode_x509_tbs_certificate(const OctetString &der_bytes, TBSCertificate &tbs_certificate)
{
    DEBUG_DUMP("", der_bytes, 16);
    OctetString value;
    int n_bytes_total = der_decode_header(der_bytes, V_ASN1_SEQUENCE, value);
    if (n_bytes_total < 0) {
        ERROR("Cannot decode header");
        return -1;
    }

    // extract the EXPLICIT tag [0] of 'version'
    OctetString version;
    int n_bytes = der_decode_header(value, 0, version);
    if (n_bytes < 0) {
        ERROR("Cannot decode version explicit tag");
        return -1;
    }

    int n_bytes_version = der_decode_integer(version, tbs_certificate.version);
    if (n_bytes_version < 0) {
        ERROR("cannot decode version");
        return -1;
    }

    value.erase(0, n_bytes);

    n_bytes = der_decode_integer(value, tbs_certificate.serial_number);
    if (n_bytes < 0) {
        ERROR("Cannot decode serial number");
        return -1;
    }
    value.erase(0, n_bytes);

    n_bytes = der_decode_x509_algorithm_identifier(value, tbs_certificate.signature);
    if (n_bytes < 0) {
        ERROR("Cannot decode signature");
        return -1;
    }
    value.erase(0, n_bytes);

    n_bytes = der_decode_x509_name(value, tbs_certificate.issuer);
    if (n_bytes < 0) {
        ERROR("Cannot decode issuer");
        return -1;
    }
    value.erase(0, n_bytes);

    n_bytes = der_decode_x509_validity(value, tbs_certificate.validity);
    if (n_bytes < 0) {
        ERROR("Cannot decode validity");
        return -1;
    }
    value.erase(0, n_bytes);

    n_bytes = der_decode_x509_name(value, tbs_certificate.subject);
    if (n_bytes < 0) {
        ERROR("Cannot decode subject");
        return -1;
    }
    value.erase(0, n_bytes);

    n_bytes = der_decode_x509_subject_public_key_info(value, tbs_certificate.subject_public_key_info);
    if (n_bytes < 0) {
        ERROR("Cannot decode subject_public_key_info");
        return -1;
    }
    value.erase(0, n_bytes);

    while (!value.empty()) {

        // There are remaining bytes. Optional fields are expected.

        size_t length;
        int tag;
        OctetString data;
        n_bytes = get_tag_length_value(value, tag, length, data);
        if (n_bytes <= 0) {
            ERROR("cannot decode tag and length");
            return -1;
        }

        value = data;
        DEBUG_DUMP("", value, 16);

        OctetString optional;
        switch (tag) {
        case 1: // issuerUniqueID
            n_bytes = der_decode_bit_string(value, tbs_certificate.issuer_unique_id);
            if (n_bytes < 0) {
                ERROR("cannot decode issuer unique id");
                return -1;
            }
            break;
        case 2: // subjectUniqueID
            n_bytes = der_decode_bit_string(value, tbs_certificate.subject_unique_id);
            if (n_bytes < 0) {
                ERROR("cannot decode subject unique id");
                return -1;
            }
            break;
        case 3: // extensions
            n_bytes = der_decode_x509_extensions(value, tbs_certificate.extensions);
            if (n_bytes < 0) {
                ERROR("cannot decode extensions");
                return -1;
            }
            break;
        default:
            ERROR("cannot decode optional fields: tag=0x%x", tag);
            return -1;
        }
        value.erase(0, n_bytes);
    }

    return n_bytes_total;
}


/**
 * @brief der_decode_x509_certificate
 * @param der_bytes
 * @param i_start
 * @param i_end
 * @param out
 * @return
 *
 * Certificate  ::=  SEQUENCE  {
 *      tbsCertificate       TBSCertificate,
 *      signatureAlgorithm   AlgorithmIdentifier,
 *      signature            BIT STRING  }
 */
int der_decode_x509_certificate(const OctetString &der_bytes, Certificate &cert)
{
    DEBUG_DUMP("", der_bytes, 16);
    OctetString value;
    int n_bytes = der_decode_header(der_bytes, V_ASN1_SEQUENCE, value);
    if (n_bytes < 0) {
        ERROR("Cannot decode header");
        return -1;
    }

    n_bytes = der_decode_x509_tbs_certificate(value, cert.tbs_certificate);
    if (n_bytes < 0) {
        ERROR("cannot decode tbs_certificate");
        return -1;
    }

    value.erase(0, n_bytes); // remove consumed bytes

    n_bytes = der_decode_x509_algorithm_identifier(value, cert.signature_algorithm);
    if (n_bytes < 0) {
        ERROR("cannot decode signature_algorithm");
        return -1;
    }

    value.erase(0, n_bytes); // remove consumed bytes

    n_bytes = der_decode_bit_string(value, cert.signature_value);
    if (n_bytes < 0) {
        ERROR("cannot decode signature_value");
        return -1;
    }

    value.erase(0, n_bytes); // remove consumed bytes

    if (!value.empty()) {
        ERROR("warning: trailing garbage bytes not decoded (too many bytes)");
    }

    return 0;
}

