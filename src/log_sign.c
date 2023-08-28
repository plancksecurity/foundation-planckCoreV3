/**
 * @file    log_sign.c
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#include "pEpEngine.h"
#include "keymanagement.h"

PEP_STATUS log_sign(
    PEP_SESSION session,
    const char *ptext,
    size_t psize,
    char **fingerprint,
    size_t **fingerprint_size,
    char **stext,
    size_t *ssize)
{
    identity_list *own_identities;
    own_identities_retrieve(session, &own_identities);
    if (!own_identities->ident) {
        return PEP_CANNOT_FIND_IDENTITY;
    }
    //PEP_STATUS status = sign_only(session, fpr, ptext, psize, stext, ssize);
    return PEP_ILLEGAL_VALUE;
}