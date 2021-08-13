/**
 * @file    src/trans_auto.h
 * @brief   transport auto functions? (FIXME: derived from filename)
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#ifndef TRANS_AUTO_H
#define TRANS_AUTO_H

#include "transport.h"

PEP_STATUS auto_configure(PEP_transport_t *transport,
        transport_config_t *config, PEP_transport_status_code *tsc);

PEP_STATUS auto_startup(PEP_transport_t *transport,
        PEP_transport_status_code *tsc);

PEP_STATUS auto_shutdown(PEP_transport_t *transport,
        PEP_transport_status_code *tsc);

PEP_STATUS auto_sendto(PEP_SESSION session, message *msg,
        PEP_transport_status_code *tsc);

PEP_STATUS auto_recvnext(PEP_SESSION session, message **msg,
        PEP_transport_status_code *tsc);

PEP_STATUS auto_notify(signal_statuschange_t status_change,
        signal_sendto_result_t sendto_result);

#endif
