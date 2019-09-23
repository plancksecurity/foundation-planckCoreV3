// This file is under GNU General Public License 3.0
// see LICENSE.txt

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
//
//      also: note that the encryption type will be used to determine what
//      gets encoded from the message struct, so if using this on an 
//      already-encrypted message, set the enc_format of the msg to PEP_enc_none.

DYNAMIC_API PEP_STATUS mime_encode_message(
        const message * msg,
        bool omit_fields,
        char **mimetext
    );


// mime_decode_message() - decode a MIME message
//
//  parameters:
//      mimetext (in)           	MIME encoded text to decode
//      size (in)               	size of text to decode
//      msg (out)               	decoded message
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

/* Carries extra return argument letting message api know if it needs to raise the attachment as 2.0/2.1 */
PEP_STATUS _mime_decode_message_internal(
        const char *mimetext,
        size_t size,
        message **msg,
        bool* raise_msg_attachment
    );

/* sometimes we don't want to transport encode */
PEP_STATUS _mime_encode_message_internal(
        const message * msg,
        bool omit_fields,
        char **mimetext,
        bool transport_encode,
        bool set_attachment_forward_comment,
        bool omit_version       
    );


#ifdef __cplusplus
}
#endif
