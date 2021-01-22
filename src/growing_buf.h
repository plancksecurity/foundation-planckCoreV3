// This file is under GNU General Public License 3.0
// see LICENSE.txt


#ifndef GROWING_BUF_H
#define GROWING_BUF_H

#include "pEpEngine.h"


#ifdef __cplusplus
extern "C" {
#endif


// this is a growing buffer, which is needed by the ASN.1 implementation
// i.e. for encoding to XER

typedef struct growing_buf {
    char *data;
    size_t size;
} growing_buf_t;


// new_growing_buf() - allocate a new growing buffer
//
//  return value:
//      new buffer or NULL if out of memory

growing_buf_t *new_growing_buf(void);


// free_growing_buf() - free growing buffer
//
//  parameters:
//      buf (in)            buffer to free

void free_growing_buf(growing_buf_t *buf);


// growing_buf_consume() - append new data to growing buffer
//
//  parameters:
//      src (in)            new data
//      size (in)           size of new data
//      dst (in)            growing buffer where new data will be appended
//
//  return value:
//      1 on succes, -1 on failure

int growing_buf_consume(const void *src, size_t size, growing_buf_t *dst);


#ifdef __cplusplus
}
#endif

#endif

