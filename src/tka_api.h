#ifndef TKA_API
#define TKA_API

#include "pEpEngine.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef PEP_STATUS (*tka_keychange_t)(
        const pEp_identity *me,
        const pEp_identity *partner,
        const char *key
    );

PEP_STATUS tka_subscribe_keychange(
        PEP_SESSION session,
        tka_keychange_t callback
    );

PEP_STATUS tka_request_temp_key(
        PEP_SESSION session,
        pEp_identity *me,
        pEp_identity *partner
    );

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // TKA_API
