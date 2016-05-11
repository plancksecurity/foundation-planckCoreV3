#include "pEp_internal.h"

#include <memory.h>
#include <assert.h>


DYNAMIC_API PEP_STATUS register_sync_callbacks(
        PEP_SESSION session,
        void *obj,
        messageToSend_t messageToSend,
        showHandshake_t showHandshake
    )
{
    session->sync_obj = obj;
    session->messageToSend = messageToSend;
    session->showHandshake = showHandshake;

    return PEP_STATUS_OK;
}

DYNAMIC_API void unregister_sync_callbacks(PEP_SESSION session) {
    session->sync_obj = NULL;
    session->messageToSend = NULL;
    session->showHandshake = NULL;
}

