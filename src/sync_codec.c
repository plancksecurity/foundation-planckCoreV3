// encoders and decoders state for DeviceGroup protocol

#include "sync_fsm.h"

// decoders

void readBeacon(const char *buf, size_t size);
void readHandshakeRequest(const char *buf, size_t size, Identity partner);
void readOwnKeys(const char *buf, size_t size, Stringlist *ownKeys);

// encoders 

void createBeacon(const char **bufp, size_t *sizep);
void createHandshakeRequest(const char **bufp, size_t *sizep, Identity partner);
void createOwnKeys(const char **bufp, size_t *sizep, Stringlist *ownKeys);
