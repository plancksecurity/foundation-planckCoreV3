#include "transport.h"

#include <stdlib.h>
#include <memory.h>
#include <assert.h>

PEP_STATUS init_transport_system(PEP_transport_t* transports)
{
    assert(PEP_trans__count == 1);
    memset(transports, 0, sizeof(PEP_transport_t) * PEP_trans__count);

    transports[0].id = PEP_trans_auto;

    return PEP_STATUS_OK;
}
