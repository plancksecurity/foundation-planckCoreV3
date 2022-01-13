/**
 * @file     tka_api.c
 * @brief    implementation of TempKey-Agreement API
 * @license  GNU General Public License 3.0 - see LICENSE.txt
 */

#include "pEp_internal.h"
#include "tka_api.h"
#include "pEpEngine.h"

#include "platform.h"

#include <stdio.h> // FIXME: remove.

PEP_STATUS tka_subscribe_keychange(
        PEP_SESSION session,
        tka_keychange_t callback
    )
{
    assert (session);
    if (! session)
        return PEP_ILLEGAL_VALUE;

    session->tka_keychange = callback;
    return PEP_STATUS_OK;
}

PEP_STATUS tka_request_temp_key(
        PEP_SESSION session,
        pEp_identity *me,
        pEp_identity *partner
    )
{
    assert (session && me && partner);
    if (! session || ! me || ! partner)
        return PEP_ILLEGAL_VALUE;

    /* FIXME: implement this.  This will have to open the channel and then
       use the protocol. */
    fprintf (stderr, "tka_request_temp_key: this is a stub\n");
    return PEP_STATUS_OK;
}
