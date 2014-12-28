#ifdef __cplusplus
extern "C" {
#endif

#include "transport.h"

PEP_STATUS encrypt_message(
        PEP_SESSION session,
        const message *src,
        stringlist_t *extra,
        message **dst
    );

PEP_STATUS decrypt_message(
        PEP_SESSION session,
        const message *src,
        message **dst
    );

#ifdef __cplusplus
}
#endif

