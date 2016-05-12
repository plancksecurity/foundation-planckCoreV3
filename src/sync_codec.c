// encoders and decoders state for DeviceGroup protocol

#include "pEpEngine.h"

// decoders

void decodeBeacon(const char **bufp, size_t *sizep);
void decodeHandshakeRequest(const char **bufp, size_t *sizep, Identity partner);
void decodeOwnKeys(const char **bufp, size_t *sizep, Stringlist *ownKeys);

// encoders 

void encodeBeacon(const char **bufp, size_t *sizep);
void encodeHandshakeRequest(const char **bufp, size_t *sizep, Identity partner);
void encodeOwnKeys(const char **bufp, size_t *sizep, Stringlist *ownKeys);
