/** @file */
/** @brief File description for doxygen missing. FIXME */

// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "pEp_internal.h"
#include "blacklist.h"

DYNAMIC_API PEP_STATUS blacklist_add(PEP_SESSION session, const char *fpr)
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session && fpr && fpr[0]);

    if (!(session && fpr && fpr[0]))
        return PEP_ILLEGAL_VALUE;

    sqlite3_exec(session->db, "BEGIN ;", NULL, NULL, NULL);

    sqlite3_reset(session->blacklist_add);
	sqlite3_bind_text(session->blacklist_add, 1, fpr, -1, SQLITE_STATIC);

    int result;

    result = sqlite3_step(session->blacklist_add);
    switch (result) {
    case SQLITE_DONE:
        status = PEP_STATUS_OK;
        sqlite3_exec(session->db, "COMMIT ;", NULL, NULL, NULL);
        break;

    default:
        sqlite3_exec(session->db, "ROLLBACK ;", NULL, NULL, NULL);
        status = PEP_UNKNOWN_ERROR;
    }

    sqlite3_reset(session->blacklist_add);
    return status;
}

DYNAMIC_API PEP_STATUS blacklist_delete(PEP_SESSION session, const char *fpr)
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session && fpr && fpr[0]);

    if (!(session && fpr && fpr[0]))
        return PEP_ILLEGAL_VALUE;

    sqlite3_reset(session->blacklist_delete);
	sqlite3_bind_text(session->blacklist_delete, 1, fpr, -1, SQLITE_STATIC);

    int result;

    result = sqlite3_step(session->blacklist_delete);
    switch (result) {
    case SQLITE_DONE:
        status = PEP_STATUS_OK;
        break;

    default:
        status = PEP_UNKNOWN_ERROR;
    }

    sqlite3_reset(session->blacklist_delete);
    return status;
}

DYNAMIC_API PEP_STATUS blacklist_is_listed(
        PEP_SESSION session,
        const char *fpr,
        bool *listed
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    int count;

    assert(session && fpr && fpr[0] && listed);

    if (!(session && fpr && fpr[0] && listed))
        return PEP_ILLEGAL_VALUE;

    *listed = false;

    sqlite3_reset(session->blacklist_is_listed);
    sqlite3_bind_text(session->blacklist_is_listed, 1, fpr, -1, SQLITE_STATIC);

    int result;

    result = sqlite3_step(session->blacklist_is_listed);
    switch (result) {
    case SQLITE_ROW:
        count = sqlite3_column_int(session->blacklist_is_listed, 0);
        *listed = count > 0;
        status = PEP_STATUS_OK;
        break;

    default:
        status = PEP_UNKNOWN_ERROR;
    }

    sqlite3_reset(session->blacklist_is_listed);
    return status;
}

DYNAMIC_API PEP_STATUS blacklist_retrieve(
        PEP_SESSION session,
        stringlist_t **blacklist
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);
    assert(blacklist);

    if (!(session && blacklist))
        return PEP_ILLEGAL_VALUE;

    *blacklist = NULL;
    stringlist_t *_blacklist = new_stringlist(NULL);
    if (_blacklist == NULL)
        goto enomem;

    sqlite3_reset(session->blacklist_retrieve);

    int result;

    stringlist_t *_bl = _blacklist;
    do {
        result = sqlite3_step(session->blacklist_retrieve);
        switch (result) {
        case SQLITE_ROW:
        {
            const char *fpr = (const char *) sqlite3_column_text(session->blacklist_retrieve, 0);

            _bl = stringlist_add(_bl, fpr);
            if (_bl == NULL)
                goto enomem;

            break;
        }
        case SQLITE_DONE:
            break;

        default:
            status = PEP_UNKNOWN_ERROR;
            result = SQLITE_DONE;
        }
    } while (result != SQLITE_DONE);

    sqlite3_reset(session->blacklist_retrieve);
    if (status == PEP_STATUS_OK)
        *blacklist = _blacklist;
    else
        free_stringlist(_blacklist);

    goto the_end;

enomem:
    free_stringlist(_blacklist);
    status = PEP_OUT_OF_MEMORY;

the_end:
    return status;
}
