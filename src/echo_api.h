/* FIXME: add a distribution_api.h #include'ing all the protocols of this family. */
#pragma once // FIXME: do it.

#include "pEpEngine.h"

DYNAMIC_API PEP_STATUS send_ping(PEP_SESSION session,
                                 pEp_identity *from,
                                 pEp_identity *to);
