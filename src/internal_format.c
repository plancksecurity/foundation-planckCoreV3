// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "platform.h"

#include "pEp_internal.h"
#include "internal_format.h"

static struct _internal_message_type {
    char type;
    char subtype;
    const char *mime_type;
} message_type[] = {
    // Keys
    { 'K',  0, "application/keys" },

    // OpenPGP
    { 'K',  2, "application/pgp-keys" },

    // x.509
    { 'K',  3, "application/pkcs10" },
    { 'K',  4, "application/pkix-cert" },
    { 'K',  5, "application/pkix-crl" },
    { 'K',  6, "application/pkcs7-mime" },
    { 'K',  7, "application/x-x509-ca-cert" },
    { 'K',  8, "application/x-x509-user-cert" },
    { 'K',  9, "application/x-pkcs7-crl" },
    { 'K', 10, "application/x-pem-file" },
    { 'K', 11, "application/x-pkcs12" },
    { 'K', 12, "application/x-pkcs7-certificates" },
    { 'K', 13, "application/x-pkcs7-certreqresp" },

    // Sync
    { 'S', 0, "application/pEp.sync" },

    // Distribution
    { 'D', 0, "application/pEp.distribution" },
    { 'D', 0, "application/pEp.keyreset" },

    // Authentication
    { 'A', 0, "application/auth" },
    { 'A', 1, "application/signature" },

    // OpenPGP
    { 'A', 2, "application/pgp-signature" },

    // x.509
    { 'A', 3, "application/pkcs7-signature" },
    { 'A', 3, "application/x-pkcs7-signature" },
    
    // end marker
    { 0, 0, NULL }
};

DYNAMIC_API PEP_STATUS encode_internal(
        const char *value,
        size_t size,
        const char *mime_type,
        char **code,
        size_t *code_size
    )
{
    assert(value && size && mime_type && code && code_size);
    if (!(value && size && mime_type && code && code_size))
        return PEP_ILLEGAL_VALUE;

    char type = 0;
    char subtype;

    struct _internal_message_type *mt;
    for (mt = message_type; mt->type; ++mt) {
        if (strcasecmp(mime_type, mt->mime_type) == 0) {
            type = mt->type;
            subtype = mt->subtype;
            break;
        }
    }

    if (!type)
        return PEP_ILLEGAL_VALUE;

    // those are more BSOBs than BLOBS, so we copy
    char *result = malloc(size + 4);
    assert(result);
    if (!result)
        return PEP_OUT_OF_MEMORY;

    result[0] = 0;
    result[1] = type;
    result[2] = subtype;
    result[3] = 0;

    memcpy(result+4, value, size);
    
    *code = result;
    *code_size = size + 4;

    return PEP_STATUS_OK;
}

DYNAMIC_API PEP_STATUS decode_internal(
        const char *code,
        size_t code_size,
        char **value,
        size_t *size,
        char **mime_type
    )
{
    assert(value && size && mime_type && code && code_size);
    if (!(value && size && mime_type && code && code_size))
        return PEP_ILLEGAL_VALUE;

    return PEP_STATUS_OK;
}

