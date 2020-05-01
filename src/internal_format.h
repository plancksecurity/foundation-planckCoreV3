// This file is under GNU General Public License 3.0
// see LICENSE.txt

#pragma once

#include "message.h"
#include "cryptotech.h"

#ifdef __cplusplus
extern "C" {
#endif

// encode_internal() - encode to the internal message format
//
//  parameters:
//      value (in)          blob
//      size (in)           size of value
//      mime_type (in)      string of MIME type
//      code (out)          blob in Internal Message Format
//      code_size (out)     size of code
//
//  caveat:
//      this function copies the data in value
//
//      code goes into the ownership of the caller
//
//  see also:
//      https://dev.pep.foundation/Engine/ElevatedAttachments

DYNAMIC_API PEP_STATUS encode_internal(
        const char *value,
        size_t size,
        const char *mime_type,
        char **code,
        size_t *code_size
    );


// decode_internal() - decode from internal message format
//
//  parameters:
//      code (in)           blob in Internal Message Format
//      code_size (in)      size of code
//      tech (in)           crypto tech for MIME type, PEP_crypt_none for auto
//      value (out)         blob or string for longmsg
//      size (out)          size of value
//      mime_type (out)     string with MIME type or NULL for longmsg
//
//  caveat:
//      this functions copies data from the code
//
//      value goes into the ownership of the caller
//      mime_type goes into the ownership of the caller
//
//      in case there is no internal message in the code a string for longmsg
//      is returned
//
//      this function copies the data in blob; in case it's called for a
//      payload it is equivalent to strndup(3), but size will include the
//      trailing 0 as code_size is expected to include the trailing 0
//      (size not length)

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
