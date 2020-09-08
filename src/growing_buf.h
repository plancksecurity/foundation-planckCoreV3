/**
 * @file    growing_buf.h
 * @brief   growing buffer, which is needed by the ASN.1 implementation
 *          i.e. for encoding to XER
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#pragma once


#include "pEpEngine.h"


#ifdef __cplusplus
extern "C" {
#endif


// this is a growing buffer, which is needed by the ASN.1 implementation
// i.e. for encoding to XER

/**
 *  @struct	growing_buf_t
 *  
 *  @brief	TODO
 *  
 */
typedef struct growing_buf {
    char *data;
    size_t size;
} growing_buf_t;


/**
 *  <!--       new_growing_buf()       -->
 *  
 *  @brief Allocate a new growing buffer
 *  
 *  @retval new buffer or NULL if out of memory
 *  
 *  
 */

growing_buf_t *new_growing_buf(void);


/**
 *  <!--       free_growing_buf()       -->
 *  
 *  @brief Free growing buffer
 *  
 *  @param[in]     buf    buffer to free
 *  
 *  
 */

void free_growing_buf(growing_buf_t *buf);


/**
 *  <!--       growing_buf_consume()       -->
 *  
 *  @brief Append new data to growing buffer
 *  
 *  @param[in]     src     new data
 *  @param[in]     size    size of new data
 *  @param[in]     dst     growing buffer where new data will be appended
 *  
 *  @retval 1 on succes, -1 on failure
 *  
 *  
 */

int growing_buf_consume(const void *src, size_t size, growing_buf_t *dst);


#ifdef __cplusplus
}
#endif

