#include "sync.h"

typedef messageToSend_t sendHandshakeRequest_t;

typedef struct _PEP_sync_callbacks_t {
    messageToSend_t messageToSend;
    showHandshake_t showHandshake;
} PEP_sync_callbacks_t;

extern PEP_sync_callbacks_t PEP_sync_callbacks;

