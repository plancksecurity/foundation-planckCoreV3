/**
 * @file        PEPMessage_codec.c
 * @brief       Implementation for PEPMessage encode and decode functions which transform message payloads to
 *              and from PER-encoded data, and XER text to and from PER
 *
 * @see         https://www.itu.int/en/ITU-T/asn1/Pages/introduction.aspx
 *
 * @license     GNU General Public License 3.0 - see LICENSE.txt
 */

#include "platform.h"

#include "distribution_codec.h"
#include "../asn.1/PEPMessage.h"
#include "pEp_internal.h"
#include "growing_buf.h"

DYNAMIC_API PEP_STATUS decode_PEPMessage_message(
        const char *data,
        size_t size,
        PEPMessage_t **msg
    )
{
    assert(data && msg);
    if (!(data && msg))
        return PEP_ILLEGAL_VALUE;

    *msg = NULL;
    PEPMessage_t *_msg = NULL;
    uper_decode_complete(NULL, &asn_DEF_PEPMessage, (void **) &_msg, data, size);
    if (!_msg)
        return PEP_PEPMESSAGE_ILLEGAL_MESSAGE;

    *msg = _msg;
    return PEP_STATUS_OK;
}

PEP_STATUS encode_PEPMessage_message(
        PEPMessage_t *msg,
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
    ssize_t _size = uper_encode_to_new_buffer(&asn_DEF_PEPMessage, NULL, msg,
            (void **) &_data);
    if (_size == -1)
        return PEP_CANNOT_ENCODE;

    *data = _data;
    *size = (size_t) _size;

    return PEP_STATUS_OK;
}

PEP_STATUS PER_to_XER_PEPMessage_msg(
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

    PEPMessage_t *msg = NULL;
    status = decode_PEPMessage_message(data, size, &msg);
    if (status)
        goto the_end;

    dst = new_growing_buf();
    if (!dst) {
        status = PEP_OUT_OF_MEMORY;
        goto the_end;
    }

    asn_enc_rval_t er = xer_encode(&asn_DEF_PEPMessage, msg, XER_F_BASIC,
            (asn_app_consume_bytes_f *) growing_buf_consume, (void *) dst);
    if (er.encoded == -1) {
        status = PEP_CANNOT_ENCODE;
        goto the_end;
    }

    *text = dst->data;
    dst->data = NULL;

the_end:
    free_growing_buf(dst);
    ASN_STRUCT_FREE(asn_DEF_PEPMessage, msg);
    return status;
}

PEP_STATUS XER_to_PER_PEPMessage_msg(
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

    PEPMessage_t *msg = NULL;
    asn_dec_rval_t dr = xer_decode(NULL, &asn_DEF_PEPMessage, (void **) &msg,
            (const void *) text, strlen(text));
    if (dr.code != RC_OK) {
        status = PEP_PEPMESSAGE_ILLEGAL_MESSAGE;
        goto the_end;
    }

    char *_data = NULL;
    size_t _size = 0;
    status = encode_PEPMessage_message(msg, &_data, &_size);
    if (status)
        goto the_end;

    *data = _data;
    *size = (size_t) _size;

the_end:
    ASN_STRUCT_FREE(asn_DEF_PEPMessage, msg);
    return status;
}

