#ifdef __cplusplus
extern "C" {
#endif

#include "transport.h"

typedef enum _PEP_enc_format {
    PEP_enc_none = 0,
    PEP_enc_MIME_multipart,
    PEP_enc_pieces
} PEP_enc_format;

PEP_STATUS encrypt_message(
        PEP_SESSION session,
        const message *src,
        stringlist_t *extra,
        message **dst,
        PEP_enc_format format
    );

PEP_STATUS decrypt_message(
        PEP_SESSION session,
        const message *src,
        message **dst
    );

#ifdef __cplusplus
}
#endif

