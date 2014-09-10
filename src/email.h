#pragma once

#include "transport.h"

PEP_STATUS email_sendto(PEP_SESSION session, const message *msg);
PEP_STATUS email_readnext(PEP_SESSION session, message **msg, PEP_transport_t **via);
