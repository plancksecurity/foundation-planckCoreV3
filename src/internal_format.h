// This file is under GNU General Public License 3.0
// see LICENSE.txt

#pragma once

#include "message.h"

#ifdef __cplusplus
extern "C" {
#endif

// encode_internal() - encode to the internal message format
//
//  parameters:
//      value (in)      blob
//      mime_type (in)  string of MIME type
//      code (out)      blob in Internal Message Format
//
//  see also:
//      https://dev.pep.foundation/Engine/ElevatedAttachments

DYNAMIC_API PEP_STATUS encode_internal(const char *value, const char *mime_type, char **code);


// decode_internal() - decode from internal message format
//
//  parameters:
//      code (in)       blob in Internal Message Format
//      value (out)     blob or string for longmsg
//      mime_type (out) string with MIME type or NULL for longmsg
//
//  caveat:
//      in case there is no internal message in the code a string for longmsg
//      is returned

DYNAMIC_API PEP_STATUS decode_internal(const char *code, char **value, char **mime_type);


#ifdef __cplusplus
}
#endif
