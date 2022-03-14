/**
 * @internal
 * @file    internal_format.h
 * @brief   internal format (FIXME: derived from filename)
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */


#ifndef INTERNAL_FORMAT_H
#define INTERNAL_FORMAT_H

#include "message.h"
#include "cryptotech.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @internal
 *  <!--       encode_internal()       -->
 *  
 *  @brief Encode to the internal message format
 *  
 *  @param[in]   value        blob
 *  @param[in]   size         size of value
 *  @param[in]   mime_type    string of MIME type
 *  @param[out]  code         blob in Internal Message Format
 *  @param[out]  code_size    size of code
 *  
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval PEP_OUT_OF_MEMORY   out of memory
 *
 *  @warning call this for the data in an attachment
 *  @warning for unsupported MIME types this function is returning NULL for code and
 *           does not fail
 *  @warning for supported MIME types this function is creating the internal message
 *           format by copying the data in value
 *  @attention code goes into the ownership of the caller
 *  @see     https://dev.pep.foundation/Engine/ElevatedAttachments
 *  
 */

DYNAMIC_API PEP_STATUS encode_internal(
        const char *value,
        size_t size,
        const char *mime_type,
        char **code,
        size_t *code_size
    );


/**
 * @internal
 *  <!--       decode_internal()       -->
 *  
 *  @brief Decode from internal message format
 *  
 *  @param[in]   code         blob in Internal Message Format
 *  @param[in]   code_size    size of code
 * <!--  @param[in]   tech         crypto tech for MIME type, PEP_crypt_none for auto. Not in function declaration  --> 
 *  @param[out]  value        blob or string for longmsg
 *  @param[out]  size         size of value
 *  @param[out]  mime_type    string with MIME type or NULL for longmsg
 *  
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval PEP_OUT_OF_MEMORY   out of memory
 *
 *  @warning    this functions copies data from the code
 *  @attention  value goes into the ownership of the caller
 *  @attention  mime_type goes into the ownership of the caller
 *  
 */

DYNAMIC_API PEP_STATUS decode_internal(
        const char *code,
        size_t code_size,
        char **value,
        size_t *size,
        char **mime_type
    );


#ifdef __cplusplus
}
#endif

#endif
