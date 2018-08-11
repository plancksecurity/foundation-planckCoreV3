// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "Sync_helper.h"
#include "pEp_internal.h"

typedef struct growing_buf {
    char *data;
    size_t size;
} growing_buf_t;

growing_buf_t *new_growing_buf(void)
{
    growing_buf_t *result = calloc(1, sizeof(growing_buf_t));
    assert(result);
    return result;
}

void free_growing_buf(growing_buf_t *buf)
{
    if (buf) {
        free(buf->data);
        free(buf);
    }
}

int consume_bytes(const void *src, size_t size, growing_buf_t *dst)
{
    assert(src && dst);
    if (!(src && dst))
        return -1;

    char *new_data = realloc(dst->data, dst->size + size + 1);
    assert(new_data);
    if (!new_data)
        return -1;
    dst->data = new_data;
    memcpy(dst->data + dst->size, src, size);
    dst->size += size;
    dst->data[dst->size] = 0; // safeguard

    return 1;
}

DYNAMIC_API PEP_STATUS decode_sync_msg(
        const char *data,
        size_t size,
        char **text
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(data && text);
    if (!(data && text))
        return PEP_ILLEGAL_VALUE;

    *text = NULL;

    Sync_t *msg = NULL;
    uper_decode_complete(NULL, &asn_DEF_Sync, (void **) &msg, data, size);
    if (!msg)
        return PEP_SYNC_ILLEGAL_MESSAGE;

    growing_buf_t *dst = new_growing_buf();
    if (!dst) {
        status = PEP_OUT_OF_MEMORY;
        goto the_end;
    }

    asn_enc_rval_t er = xer_encode(&asn_DEF_Sync, msg, XER_F_BASIC,
            (asn_app_consume_bytes_f *) consume_bytes, (void *) dst);
    if (er.encoded == -1) {
        status = PEP_CANNOT_ENCODE;
        goto the_end;
    }

    *text = dst->data;
    dst->data = NULL;

the_end:
    free_growing_buf(dst);
    ASN_STRUCT_FREE(asn_DEF_Sync, msg);
    return status;
}

DYNAMIC_API PEP_STATUS encode_sync_msg(
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

    Sync_t *msg = NULL;
    asn_dec_rval_t dr = xer_decode(NULL, &asn_DEF_Sync, (void **) &msg,
            (const void *) text, strlen(text));
    if (dr.code != RC_OK) {
        status = PEP_SYNC_ILLEGAL_MESSAGE;
        goto the_end;
    }

    char *payload = NULL;
    ssize_t _size = uper_encode_to_new_buffer(&asn_DEF_Sync, NULL, msg,
            (void **) &payload);
    if (_size == -1) {
        status = PEP_CANNOT_ENCODE;
        goto the_end;
    }

    *data = payload;
    *size = (size_t) _size;

the_end:
    ASN_STRUCT_FREE(asn_DEF_Sync, msg);
    return status;
}

