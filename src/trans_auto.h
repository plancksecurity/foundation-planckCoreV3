/**
 * @file    src/trans_auto.h
 * @brief   transport auto functions? (FIXME: derived from filename)
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#pragma once

#include "transport.h"

PEP_STATUS auto_sendto(PEP_SESSION session, const message *msg);
/**
 *  <!--       auto_readnext()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	session		PEP_SESSION
 *  @param[in]	**msg		message
 *  @param[in]	**via		PEP_transport_t
 *  
 */
PEP_STATUS auto_readnext(PEP_SESSION session, message **msg, PEP_transport_t **via);
