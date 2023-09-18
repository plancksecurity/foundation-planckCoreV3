/**
 * @file    signature.c
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#include <stdlib.h>
#include <string.h>

#include "signature.h"

#include "keymanagement.h"
#include "pEpEngine.h"
#include "pEpEngine_internal.h"
#include "pEp_debug.h"

PEP_STATUS
create_signing_identity(PEP_SESSION session, pEp_identity **signer_identity)
{
    char *default_user_id = NULL;
    PEP_STATUS status_own_userid = get_default_own_userid(session, &default_user_id);

    *signer_identity = new_identity(SIGNING_IDENTITY_USER_ADDRESS,
                                    NULL,
                                    default_user_id ? default_user_id : PEP_OWN_USERID,
                                    SIGNING_IDENTITY_USER_NAME);

    if (status_own_userid == PEP_STATUS_OK) {
        free(default_user_id);
        default_user_id = NULL;
    }

    PEP_STATUS status = myself(session, *signer_identity);
    if (status != PEP_STATUS_OK) {
        return status;
    }

    // Opt out of key sync for this special signing identity.
    status = set_identity_flags(session, *signer_identity, PEP_idf_not_for_sync);
    return status;
}

DYNAMIC_API PEP_STATUS
signature_for_text(PEP_SESSION session,
                   const char *ptext,
                   size_t psize,
                   char **stext,
                   size_t *ssize)
{
    PEP_REQUIRE(session && ptext);

    pEp_identity *the_signing_identity = NULL;
    PEP_STATUS status = create_signing_identity(session, &the_signing_identity);

    if (status != PEP_STATUS_OK) {
        return status;
    }

    status = sign_only(session, ptext, psize, the_signing_identity->fpr, stext, ssize);

    return status;
}

DYNAMIC_API PEP_STATUS
verify_signature(PEP_SESSION session,
                 const char *ptext,
                 size_t psize,
                 const char *stext,
                 size_t ssize)
{
    stringlist_t *keylist = NULL; // not used, but needed to satisfy the API
    PEP_STATUS status = verify_text(session, ptext, psize, stext, ssize, &keylist);
    free_stringlist(keylist);
    return status;
}
