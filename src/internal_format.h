/**
 * @file    internal_format.h
 * @brief   internal format (FIXME: derived from filename)
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#pragma once

#include "message.h"
#include "cryptotech.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  <!--       encode_internal()       -->
 *  
 *  @brief Encode to the internal message format
 *  
 *  @param[in]     value        blob
 *  @param[in]     size         size of value
 *  @param[in]     mime_type    string of MIME type
 *  @param[out]    code         blob in Internal Message Format
 *  @param[out]    code_size    size of code
 *  
 *  @warning call this for the data in an attachment
 *           for unsupported MIME types this function is returning NULL for code and
 *           does not fail
 *           for supported MIME types this function is creating the internal message
 *           format by copying the data in value
 *           code goes into the ownership of the caller
 *           see also:
 *           https://dev.pep.foundation/Engine/ElevatedAttachments
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
 *  <!--       decode_internal()       -->
 *  
 *  @brief Decode from internal message format
 *  
 *  @param[in]     code         blob in Internal Message Format
 *  @param[in]     code_size    size of code
 *  @param[in]     tech         crypto tech for MIME type, PEP_crypt_none for auto
 *  @param[out]    value        blob or string for longmsg
 *  @param[out]    size         size of value
 *  @param[out]    mime_type    string with MIME type or NULL for longmsg
 *  
 *  @warning this functions copies data from the code
 *           value goes into the ownership of the caller
 *           mime_type goes into the ownership of the caller
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
