/**
 * @file    log_sign.c
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#include <stdlib.h>
#include <string.h>

#include "log_sign.h"

#include "pEpEngine.h"
#include "pEpEngine_internal.h"
#include "keymanagement.h"
#include "pEp_debug.h"

PEP_STATUS log_sign(
    PEP_SESSION session,
    const char *ptext,
    size_t psize,
    char **stext,
    size_t *ssize)
{
    PEP_REQUIRE(session && ptext);

    identity_list *own_identities;
    own_identities_retrieve(session, &own_identities);
    if (!own_identities->ident)
    {
        return PEP_CANNOT_FIND_IDENTITY;
    }

    PEP_STATUS status = sign_only(session, ptext, psize, own_identities->ident->fpr, stext, ssize);

    return status;
}

PEP_STATUS log_verify(
    PEP_SESSION session,
    const char *ptext,
    size_t psize,
    const char *stext,
    size_t ssize)
{
    stringlist_t *keylist;
    PEP_STATUS status = verify_text(session, ptext, psize, stext, ssize, &keylist);
    free_stringlist(keylist);
    return status;
}
