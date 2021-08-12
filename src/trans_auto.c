/** @file */
/** @brief File description for doxygen missing. FIXME */

// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "trans_auto.h"

PEP_STATUS auto_init(PEP_transport_t *transport,
        PEP_SESSION session, PEP_transport_status_code *tsc)
{

    return PEP_STATUS_OK;
}

PEP_STATUS auto_sendto(PEP_SESSION session, message *msg,
        stringlist_t **unreachable_addresses, PEP_transport_status_code *tsc)
{

    return PEP_STATUS_OK;
}

PEP_STATUS auto_readnext(PEP_SESSION session, message **msg,
        PEP_transport_status_code *tsc)
{

    return PEP_STATUS_OK;
}

PEP_STATUS auto_signal_statuschange(PEP_transport_id id,
        PEP_transport_status_code tsc)
{

    return PEP_STATUS_OK;
}

