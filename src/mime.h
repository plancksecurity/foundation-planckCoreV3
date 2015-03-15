#pragma once

#include "message.h"

#ifdef __cplusplus
extern "C" {
#endif


// is_PGP_message_text() - determine if text encodes a PGP message
//
//  parameters:
//      text (in)               text to examine
//
//  return value:
//      true if text is a PGP message, false otherwise

DYNAMIC_API bool is_PGP_message_text(const char *text);


// mime_encode_message() - encode a MIME message
//
//  parameters:
//      msg (in)                message to encode
//      omit_fields (in)        only encode message body and attachments
//      mimetext (out)          the resulting encoded text or NULL on any error
//
//  return value:
//      PEP_STATUS_OK           if everything worked
//      PEP_BUFFER_TOO_SMALL    if encoded message size is too big to handle
//      PEP_CANNOT_CREATE_TEMP_FILE
//                              if there are issues with temp files; in
//                              this case errno will contain the underlying
//                              error
//      PEP_OUT_OF_MEMORY       if not enough memory could be allocated
//
//  caveat:
//      the resulttext will go to the ownership of the caller
//      the message will remain in the ownership of the caller
//      omit_fields is true for payload of PGP/MIME messages

DYNAMIC_API PEP_STATUS mime_encode_message(
        const message * msg,
        bool omit_fields,
        char **mimetext
    );


// mime_decode_message() - decode a MIME message
//
//  parameters:
//      mimetext (in)           MIME encoded text to decode
//      msg (out)               decoded message
//
//  return value:
//      PEP_STATUS_OK           if everything worked
//      PEP_BUFFER_TOO_SMALL    if encoded message size is too big to handle
//      PEP_CANNOT_CREATE_TEMP_FILE
//                              if there are issues with temp files; in
//                              this case errno will contain the underlying
//                              error
//      PEP_OUT_OF_MEMORY       if not enough memory could be allocated
//
//  caveat:
//      the decoded message will go to the ownership of the caller; mimetext
//      will remain in the ownership of the caller

DYNAMIC_API PEP_STATUS mime_decode_message(
        const char *mimetext,
        message **msg
    );

#ifdef __cplusplus
}
#endif

