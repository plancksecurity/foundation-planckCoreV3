#pragma once

#include "pEpEngine.h"

#ifdef __cplusplus
extern "C" {
#endif


// mime_encode_text() - encode a MIME message
//
//  parameters:
//      plaintext (in)          plaintext of message as UTF-8 string
//      htmltext (in)           optional HTML version of message as UTF-8
//                              string or NULL if it does not apply
//      resulttext (out)        the resulting encoded text or NULL on any error
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
//      the resulttext will go to the ownership of the caller; plaintext
//      and htmltext will remain in the ownership of the caller

DYNAMIC_API PEP_STATUS mime_encode_text(
        const char *plaintext,
        const char *htmltext,
        char **resulttext
    );

#ifdef __cplusplus
}
#endif

