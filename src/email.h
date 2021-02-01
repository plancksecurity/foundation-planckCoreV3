/**
 * @file    email.h
 * @brief   email (FIXME: derived from filename)
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */


#ifndef EMAIL_H
#define EMAIL_H

#include "transport.h"

/**
 *  <!--       email_sendto()       -->
 *
 *  @brief			TODO
 *
 *  @param[in]  session      PEP_SESSION
 *  @param[in]  msg          message*
 *
 */
PEP_STATUS email_sendto(PEP_SESSION session, const message *msg);

/**
 *  <!--       email_readnext()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session      PEP_SESSION
 *  @param[in]  msg          message**
 *  @param[in]  via          PEP_transport_t**
 *  
 */
PEP_STATUS email_readnext(PEP_SESSION session, message **msg, PEP_transport_t **via);

#endif
