/**
 * @file    log_sign.c
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#include <stdlib.h>

#include "log_sign.h"

#include "pEpEngine.h"
#include "pEpEngine_internal.h"
#include "keymanagement.h"
#include "pEp_debug.h"

PEP_STATUS log_sign(
    PEP_SESSION session,
    const char *ptext,
    size_t psize,
    char **fingerprint,
    size_t *fingerprint_size,
    char **stext,
    size_t *ssize)
{
    PEP_REQUIRE(session && ptext && fingerprint && fingerprint_size);

    identity_list *own_identities;
    own_identities_retrieve(session, &own_identities);
    if (!own_identities->ident)
    {
        return PEP_CANNOT_FIND_IDENTITY;
    }

    PEP_STATUS status = sign_only(session, own_identities->ident->fpr, ptext, psize, stext, ssize);

    return status;
}