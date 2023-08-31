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

PEP_STATUS signing_identity(PEP_SESSION session, pEp_identity **signer_identity)
{
    *signer_identity = new_identity(AUDIT_LOG_USER_ADDRESS,
                                    NULL,
                                    PEP_OWN_USERID,
                                    AUDIT_LOG_USER_NAME);
    PEP_STATUS status = myself(session, *signer_identity);
    if (status != PEP_STATUS_OK)
    {
        return status;
    }

    status = set_identity_flags(session, signer_identity, PEP_idf_not_for_sync);
    return status;
}

PEP_STATUS log_sign(
    PEP_SESSION session,
    const char *ptext,
    size_t psize,
    char **stext,
    size_t *ssize)
{
    PEP_REQUIRE(session && ptext);

    pEp_identity *the_signing_identity = NULL;
    PEP_STATUS status = signing_identity(session, &the_signing_identity);

    if (status != PEP_STATUS_OK)
    {
        return status;
    }

    status = sign_only(session, ptext, psize, the_signing_identity->fpr, stext, ssize);

    return status;
}

PEP_STATUS log_verify(
    PEP_SESSION session,
    const char *ptext,
    size_t psize,
    const char *stext,
    size_t ssize)
{
    stringlist_t *keylist; // TODO: Remove?
    PEP_STATUS status = verify_text(session, ptext, psize, stext, ssize, &keylist);
    free_stringlist(keylist);
    return status;
}
