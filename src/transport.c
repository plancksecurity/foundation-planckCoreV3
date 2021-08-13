/** @file */
/** @brief File description for doxygen missing. FIXME */

// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "pEp_internal.h"
#include "trans_auto.h"

#include <memory.h>
#include <assert.h>

PEP_transport_t transports[PEP_trans__count];
    
PEP_STATUS init_transport_system(PEP_SESSION session, bool in_first)
{
    assert(session);
    session->transports = transports;

    if (in_first) {
        assert(PEP_trans__count == 1);
        memset(transports, 0, sizeof(PEP_transport_t) * PEP_trans__count);

        transports[PEP_trans_auto].id = PEP_trans_auto;
        transports[PEP_trans_auto].uri_scheme = "";

        transports[PEP_trans_auto].configure = auto_configure;
        transports[PEP_trans_auto].startup = auto_startup;
        transports[PEP_trans_auto].shutdown = auto_shutdown;

        transports[PEP_trans_auto].sendto = auto_sendto;
        transports[PEP_trans_auto].recvnext = auto_recvnext;

        transports[PEP_trans_auto].notify = auto_notify;
    }

    return PEP_STATUS_OK;
}

void release_transport_system(PEP_SESSION session, bool out_last)
{
    assert(session);
    // nothing yet
}

