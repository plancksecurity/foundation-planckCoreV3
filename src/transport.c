#include "pEp_internal.h"
#include "trans_auto.h"

#include <memory.h>
#include <assert.h>

PEP_STATUS init_transport_system(PEP_SESSION session, bool in_first)
{
    static PEP_transport_t transports[PEP_trans__count];
    
    assert(session);
    session->transports = transports;

    if (in_first) {
        assert(PEP_trans__count == 1);
        memset(transports, 0, sizeof(PEP_transport_t) * PEP_trans__count);

        transports[PEP_trans_auto].id = PEP_trans_auto;
        transports[PEP_trans_auto].sendto = auto_sendto;
        transports[PEP_trans_auto].readnext = auto_readnext;
    }

    return PEP_STATUS_OK;
}

void release_transport_system(PEP_SESSION session, bool out_last)
{
    assert(session);
    // nothing yet
}

