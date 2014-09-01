#pragma once

#include "pEpEngine.h"

typedef enum _PEP_transports {
    PEP_trans_auto = 0,
//    PEP_trans_email = 1,
//    PEP_trans_whatsapp = 2,

    PEP_trans__count
} PEP_transports;

typedef struct _PEP_transport_t PEP_transport_t;

typedef PEP_STATUS (*sendto_t)(PEP_SESSION session, const pEp_identity *address, const char *shortmsg, const char *longmsg, const char *longmsg_formatted);
typedef PEP_STATUS (*readnext_t)(PEP_SESSION session, pEp_identity *from, pEp_identity *reached, char **shortmsg, size_t shortmsg_size, char ** longmsg, size_t longmsg_size, char ** longmsg_formatted, size_t longmsg_formatted_size, PEP_transport_t **via);

struct _PEP_transport_t {
    uint8_t id;
    sendto_t sendto;
    readnext_t readnext;
};

typedef uint64_t transports_mask;
