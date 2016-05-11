#include "pEp_internal.h"
#include "sync_internal.h"

#include <memory.h>
#include <assert.h>


PEP_sync_callbacks_t PEP_sync_callbacks = { NULL, NULL };

DYNAMIC_API PEP_STATUS register_sync_callbacks(
        messageToSend_t messageToSend,
        showHandshake_t showHandshake
    )
{
    PEP_sync_callbacks.messageToSend = messageToSend;
    PEP_sync_callbacks.showHandshake = showHandshake;

    return PEP_STATUS_OK;
}

DYNAMIC_API void unregister_sync_callbacks(PEP_SESSION session) {
    PEP_sync_callbacks.messageToSend = NULL;
    PEP_sync_callbacks.showHandshake = NULL;
}

