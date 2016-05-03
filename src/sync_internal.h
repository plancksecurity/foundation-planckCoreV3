#include "sync.h"

typedef struct _PEP_sync_callbacks_t {
    sendBeacon_t sendBeacon;
    sendHandshakeRequest_t sendHandshakeRequest;
    showHandshake_t showHandshake;
} PEP_sync_callbacks_t;

extern PEP_sync_callbacks_t PEP_sync_callbacks;

