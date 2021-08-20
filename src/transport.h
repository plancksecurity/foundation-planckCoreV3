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
 *  @enum    PEP_transport_id
 *  
 *  @brief    TODO
 *  
 */
typedef enum _PEP_transport_id {
    // auto transport chooses transport per message automatically
    PEP_trans_auto = 0,
//    PEP_trans_Email = 0x01,
//    PEP_trans_RCE = 0x02,
//    PEP_trans_PDL = 0x03,

    PEP_trans__count,
    PEP_trans_CC = 0xfe
} PEP_transport_id;

typedef struct _transport_config {
    // set size field when initializing
    size_t size;

    // expand here
    // in C++ this must be POD
} transport_config_t;

// transports are delivering the transport status code
// this is defined here:
// https://dev.pep.foundation/Engine/TransportStatusCode

typedef uint32_t PEP_transport_status_code;

typedef struct _PEP_transport_t PEP_transport_t;

// functions offered by transport

typedef PEP_STATUS (*configure_transport_t)(PEP_transport_t *transport,
        transport_config_t *config, PEP_transport_status_code *tsc);

typedef PEP_STATUS (*startup_transport_t)(PEP_transport_t *transport,
        PEP_transport_status_code *tsc);

typedef PEP_STATUS (*shutdown_transport_t)(PEP_transport_t *transport,
        PEP_transport_status_code *tsc);

typedef PEP_STATUS (*sendto_t)(PEP_SESSION session, message *msg,
        PEP_transport_status_code *tsc);

typedef PEP_STATUS (*recvnext_t)(PEP_SESSION session, message **msg,
        PEP_transport_status_code *tsc);

// callbacks

typedef PEP_STATUS (*signal_statuschange_t)(PEP_transport_id id,
        PEP_transport_status_code tsc);

typedef PEP_STATUS (*signal_sendto_result_t)(PEP_transport_id id, char *message_id,
        char *address, PEP_transport_status_code tsc);

typedef PEP_STATUS (*signal_incoming_message_t)(PEP_transport_id id,
        PEP_transport_status_code tsc);

// call this to receive signals

typedef enum _callback_execution {
    PEP_cbe_polling = 0,    // execute callbacks immediately only
    PEP_cbe_async,          // execute callbacks multiple times later on any
                            // thread; call with PEP_cbe_polling to disable

    // the last one is for the transport system only
    // do not implement it in transports
    PEP_cbe_blocking = 255
} callback_execution;

// provide NULL for callbacks to avoid being called

typedef PEP_STATUS (*notify_transport_t)(signal_statuschange_t status_change,
        signal_sendto_result_t sendto_result,
        signal_incoming_message_t incoming, callback_execution cbe);

/**
 *  @struct    _PEP_transport_t
 *  
 *  @brief    TODO
 *  
 */
struct _PEP_transport_t {
    PEP_transport_id id;                    // transport ID
    const char *uri_scheme;                 // URI scheme this transport is
                                            // covering

    // functions offered by transport

    configure_transport_t configure;
    startup_transport_t startup;
    shutdown_transport_t shutdown;

    sendto_t sendto;
    recvnext_t recvnext;

    notify_transport_t notify;

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
