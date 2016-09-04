#include "asn1_helper.h"
#include <assert.h>
#include <stdlib.h>

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

