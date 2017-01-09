// This file is under GNU General Public License 3.0
// see LICENSE.txt

#pragma once

#include <string.h>

typedef struct growing_buf {
    char *data;
    size_t size;
} growing_buf_t;

growing_buf_t *new_growing_buf(void);
void free_growing_buf(growing_buf_t *buf);
int consume_bytes(const void *src, size_t size, growing_buf_t *dst);

