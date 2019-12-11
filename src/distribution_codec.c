// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "platform.h"

#include "distribution_codec.h"
#include "../asn.1/Distribution.h"
#include "pEp_internal.h"
#include "growing_buf.h"

DYNAMIC_API PEP_STATUS decode_Distribution_message(
        const char *data,
        size_t size,
        Distribution_t **msg
    )
{
    assert(data && msg);
    if (!(data && msg))
        return PEP_ILLEGAL_VALUE;

    *msg = NULL;
    Distribution_t *_msg = NULL;
    uper_decode_complete(NULL, &asn_DEF_Distribution, (void **) &_msg, data, size);
    if (!_msg)
        return PEP_DISTRIBUTION_ILLEGAL_MESSAGE;

    *msg = _msg;
    return PEP_STATUS_OK;
}

PEP_STATUS encode_Distribution_message(
        Distribution_t *msg,
        char **data,
        size_t *size
    )
{
    assert(data && msg);
    if (!(data && msg))
        return PEP_ILLEGAL_VALUE;

    *data = NULL;
    *size = 0;

    char *_data = NULL;
    ssize_t _size = uper_encode_to_new_buffer(&asn_DEF_Distribution, NULL, msg,
            (void **) &_data);
    if (_size == -1)
        return PEP_CANNOT_ENCODE;

    *data = _data;
    *size = (size_t) _size;

    return PEP_STATUS_OK;
}

PEP_STATUS PER_to_XER_Distribution_msg(
        const char *data,
        size_t size,
        char **text
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    growing_buf_t *dst = NULL;

    assert(data && text);
    if (!(data && text))
        return PEP_ILLEGAL_VALUE;

    *text = NULL;

    Distribution_t *msg = NULL;
    status = decode_Distribution_message(data, size, &msg);
    if (status)
        goto the_end;

    dst = new_growing_buf();
    if (!dst) {
        status = PEP_OUT_OF_MEMORY;
        goto the_end;
    }

    asn_enc_rval_t er = xer_encode(&asn_DEF_Distribution, msg, XER_F_BASIC,
            (asn_app_consume_bytes_f *) growing_buf_consume, (void *) dst);
    if (er.encoded == -1) {
        status = PEP_CANNOT_ENCODE;
        goto the_end;
    }

    *text = dst->data;
    dst->data = NULL;

the_end:
    free_growing_buf(dst);
    ASN_STRUCT_FREE(asn_DEF_Distribution, msg);
    return status;
}

PEP_STATUS XER_to_PER_Distribution_msg(
        const char *text,
        char **data,
        size_t *size
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(text && data && size);
    if (!(text && data && size))
        return PEP_ILLEGAL_VALUE;

    *data = NULL;
    *size = 0;

    Distribution_t *msg = NULL;
    asn_dec_rval_t dr = xer_decode(NULL, &asn_DEF_Distribution, (void **) &msg,
            (const void *) text, strlen(text));
    if (dr.code != RC_OK) {
        status = PEP_DISTRIBUTION_ILLEGAL_MESSAGE;
        goto the_end;
    }

    char *_data = NULL;
    size_t _size = 0;
    status = encode_Distribution_message(msg, &_data, &_size);
    if (status)
        goto the_end;

    *data = _data;
    *size = (size_t) _size;

the_end:
    ASN_STRUCT_FREE(asn_DEF_Distribution, msg);
    return status;
}

