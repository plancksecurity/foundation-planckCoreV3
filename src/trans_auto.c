/** 
 * @file trans_auto.c
 * @brief File description for doxygen missing. FIXME 
 * This file is under GNU General Public License 3.0 - see LICENSE.txt
 */

#include "trans_auto.h"

PEP_STATUS auto_configure(PEP_transport_t *transport,
        transport_config_t *config, PEP_transport_status_code *tsc)
{

    return PEP_STATUS_OK;
}

PEP_STATUS auto_startup(PEP_transport_t *transport,
        PEP_transport_status_code *tsc)
{

    return PEP_STATUS_OK;
}

PEP_STATUS auto_shutdown(PEP_transport_t *transport,
        PEP_transport_status_code *tsc)
{

    return PEP_STATUS_OK;
}

PEP_STATUS auto_sendto(PEP_SESSION session, message *msg,
        PEP_transport_status_code *tsc)
{

    return PEP_STATUS_OK;
}

PEP_STATUS auto_recvnext(PEP_SESSION session, message **msg,
        PEP_transport_status_code *tsc)
{

    return PEP_STATUS_OK;
}

PEP_STATUS auto_notify(signal_statuschange_t status_change,
        signal_sendto_result_t sendto_result,
        signal_incoming_message_t incoming, callback_execution cbe)
{

    return PEP_STATUS_OK;
}

