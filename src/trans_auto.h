#pragma once

#include "transport.h"

PEP_STATUS auto_sendto(PEP_SESSION session, const message *msg);
PEP_STATUS auto_readnext(PEP_SESSION session, message **msg, PEP_transport_t **via);
