/**
 * @file    transport.h
 * @brief   transport structs
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#ifndef TRANSPORT_H
#define TRANSPORT_H

#include "pEpEngine.h"
#include "message.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  @enum    PEP_transports
 *  
 *  @brief    TODO
 *  
 */
typedef enum _PEP_transports {
    // auto transport chooses transport per message automatically
    PEP_trans_auto = 0,
//    PEP_trans_email,
//    PEP_trans_whatsapp,

    PEP_trans__count
} PEP_transports;

// transports are delivering the transport status code
// this is defined here:
// https://dev.pep.foundation/Engine/TransportStatusCode

typedef uint32_t PEP_transport_status_code;

typedef struct _PEP_transport_t PEP_transport_t;

typedef PEP_STATUS (*sendto_t)(PEP_SESSION session, message *msg,
        PEP_transport_status_code *tsc);

typedef PEP_STATUS (*recvnext_t)(PEP_SESSION session, message **msg,
        PEP_transport_status_code *tsc);

/**
 *  @struct    _PEP_transport_t
 *  
 *  @brief    TODO
 *  
 */
struct _PEP_transport_t {
    PEP_transports id;                      // transport ID

    sendto_t sendto;                        // sendto function
    recvnext_t readnext;                    // readnext function

    bool is_online_transport;

    bool shortmsg_supported;
    bool longmsg_supported;
    bool longmsg_formatted_supported;

    PEP_text_format native_text_format;     // native format of the transport
};

extern PEP_transport_t transports[PEP_trans__count];

typedef uint64_t transports_mask;

#ifdef __cplusplus
}
#endif

#endif
