/**
 * @file        message_codec.c
 * @brief       Implementation for ASN1Message encode and decode functions which transform message payloads to
 *              and from PER-encoded data, and XER text to and from PER
 *
 * @see         https://www.itu.int/en/ITU-T/asn1/Pages/introduction.aspx
 *
 * @license     GNU General Public License 3.0 - see LICENSE.txt
 */

#include "platform.h"

#include "distribution_codec.h"
#include "../asn.1/ASN1Message.h"
#include "pEp_internal.h"
#include "growing_buf.h"
#include "message_codec.h"

DYNAMIC_API PEP_STATUS decode_ASN1Message_message(
        const char *data,
        size_t size,
        ASN1Message_t **msg
    )
{
    assert(data && msg);
    if (!(data && msg))
        return PEP_ILLEGAL_VALUE;

    *msg = NULL;
    ASN1Message_t *_msg = NULL;

    asn_codec_ctx_t s_codec_ctx;
    memset(&s_codec_ctx, 0, sizeof(s_codec_ctx));
#ifdef DEBUG
    // ASAN blows up the stack quite a lot. Increase the maximum that is allowed.
    s_codec_ctx.max_stack_size = ASN__DEFAULT_STACK_MAX * 100;
#else
    s_codec_ctx.max_stack_size = ASN__DEFAULT_STACK_MAX;
#endif

    uper_decode_complete(&s_codec_ctx, &asn_DEF_ASN1Message, (void **) &_msg, data, size);
    if (!_msg)
        return PEP_PEPMESSAGE_ILLEGAL_MESSAGE;

    *msg = _msg;
    return PEP_STATUS_OK;
}

DYNAMIC_API PEP_STATUS encode_ASN1Message_message(
        ASN1Message_t *msg,
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
    ssize_t _size = uper_encode_to_new_buffer(&asn_DEF_ASN1Message, NULL, msg,
            (void **) &_data);
    if (_size == -1)
        return PEP_CANNOT_ENCODE;

    *data = _data;
    *size = (size_t) _size;

    return PEP_STATUS_OK;
}

DYNAMIC_API PEP_STATUS PER_to_XER_ASN1Message_msg(
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

    ASN1Message_t *msg = NULL;
    status = decode_ASN1Message_message(data, size, &msg);
    if (status)
        goto the_end;

    dst = new_growing_buf();
    if (!dst) {
        status = PEP_OUT_OF_MEMORY;
        goto the_end;
    }

    asn_enc_rval_t er = xer_encode(&asn_DEF_ASN1Message, msg, XER_F_BASIC,
            (asn_app_consume_bytes_f *) growing_buf_consume, (void *) dst);
    if (er.encoded == -1) {
        status = PEP_CANNOT_ENCODE;
        goto the_end;
    }

    *text = dst->data;
    dst->data = NULL;

the_end:
    free_growing_buf(dst);
    free_ASN1Message(msg);
    return status;
}

DYNAMIC_API PEP_STATUS XER_to_PER_ASN1Message_msg(
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

    ASN1Message_t *msg = NULL;
    asn_dec_rval_t dr = xer_decode(NULL, &asn_DEF_ASN1Message, (void **) &msg,
            (const void *) text, strlen(text));
    if (dr.code != RC_OK) {
        status = PEP_PEPMESSAGE_ILLEGAL_MESSAGE;
        goto the_end;
    }

    char *_data = NULL;
    size_t _size = 0;
    status = encode_ASN1Message_message(msg, &_data, &_size);
    if (status)
        goto the_end;

    *data = _data;
    *size = (size_t) _size;

the_end:
    free_ASN1Message(msg);
    return status;
}

DYNAMIC_API void free_ASN1Message(
        ASN1Message_t *msg
    )
{
    ASN_STRUCT_FREE(asn_DEF_ASN1Message, msg);
}
