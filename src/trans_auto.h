/**
 * @file    src/trans_auto.h
 * @brief   transport auto functions? (FIXME: derived from filename)
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#ifndef TRANS_AUTO_H
#define TRANS_AUTO_H

#include "transport.h"

PEP_STATUS auto_sendto(PEP_SESSION session, message *msg,
        PEP_transport_status_code *tsc);

/**
 *  <!--       auto_readnext()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]   session      PEP_SESSION
 *  @param[out]  msg          message**
 *  @param[out]  via          PEP_transport_t**
 *  
 */

PEP_STATUS auto_readnext(PEP_SESSION session, message **msg,
        PEP_transport_status_code *tsc);

#endif
