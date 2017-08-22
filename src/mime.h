// This file is under GNU General Public License 3.0
// see LICENSE.txt

#pragma once

#include "message.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PEP_CONTENT_DISP_ATTACHMENT = 0,
    PEP_CONTENT_DISP_INLINE = 1,
    PEP_CONTENT_DISP_EXTENSION = 2,
    PEP_CONTENT_DISP_NONE = -1      // must be affirmatively set
} content_disposition_type;

DYNAMIC_API void set_blob_content_disposition(bloblist_t* blob, 
                                              content_disposition_type disposition,
                                              const char* extension_typename,
                                              stringpair_list_t dispo_params);


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
//      size (in)               size of text to decode
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
        size_t size,
        message **msg
    );

#ifdef __cplusplus
}
#endif
