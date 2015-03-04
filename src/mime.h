#pragma once

#include "transport.h"

#ifdef __cplusplus
extern "C" {
#endif


// mime_encode_text() - encode a MIME message
//
//  parameters:
//      plaintext (in)          plaintext of message as UTF-8 string
//      htmltext (in)           optional HTML version of message as UTF-8
//                              string or NULL if it does not apply
//      attachments (in)        attatchments or NULL if there are none
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
//      the resulttext will go to the ownership of the caller; plaintext,
//      htmltext and attachments will remain in the ownership of the caller

DYNAMIC_API PEP_STATUS mime_encode_text(
        const char *plaintext,
        const char *htmltext,
        bloblist_t *attachments,
        char **mimetext
    );


// mime_decode_text() - decode a MIME message
//
//  parameters:
//      mimetext (in)           MIME encoded text to decode
//      plaintext (out)         plaintext of message as UTF-8 string
//      htmltext (out)          optional HTML version of message as UTF-8
//                              string or NULL if it does not apply
//      attachments (out)       attatchments or NULL if there are none
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
//      plaintext, htmltext and attachments will go to the ownership of the
//      caller; mimetext will remain in the ownership of the caller

DYNAMIC_API PEP_STATUS mime_decode_text(
        const char *mimetext,
        char **plaintext,
        char **htmltext,
        bloblist_t **attachments
    );

#ifdef __cplusplus
}
#endif

