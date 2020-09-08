/**
 * @file    transport.h
 * @brief   transport structs
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#pragma once

#include "pEpEngine.h"
#include "message.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  @enum	PEP_transports
 *  
 *  @brief	TODO
 *  
 */
typedef enum _PEP_transports {
    // auto transport chooses transport per message automatically
    PEP_trans_auto = 0,
//    PEP_trans_email,
//    PEP_trans_whatsapp,

    PEP_trans__count
} PEP_transports;

typedef struct _PEP_transport_t PEP_transport_t;

typedef PEP_STATUS (*sendto_t)(PEP_SESSION session, const message *msg);
typedef PEP_STATUS (*readnext_t)(PEP_SESSION session, message **msg,
        PEP_transport_t **via);

/**
 *  @struct	_PEP_transport_t
 *  
 *  @brief	TODO
 *  
 */
struct _PEP_transport_t {
    uint8_t id;                             // transport ID
    sendto_t sendto;                        // sendto function
    readnext_t readnext;                    // readnext function
    bool long_message_supported;            // flag if this transport supports
                                            // long messages
    bool formatted_message_supported;       // flag if this transport supports
                                            // formatted messages
    PEP_text_format native_text_format;     // native format of the transport
};

extern PEP_transport_t transports[PEP_trans__count];

typedef uint64_t transports_mask;

#ifdef __cplusplus
}
#endif

