// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "pEp_internal.h"
#include "map_asn1.h"

#include "Sync_impl.h"
#include "KeySync_fsm.h"

PEP_STATUS deviceGrouped(PEP_SESSION session, bool *result)
{
    assert(session && result);
    if (!(session && result))
        return PEP_ILLEGAL_VALUE;

    static const char *sql = "select count(*) from identity where user_id = '"PEP_OWN_USERID"' and (flags & 4) = 4;";
    static const size_t len = sizeof("select count(*) from identity where user_id = '"PEP_OWN_USERID"' and (flags & 4) = 4;");
    sqlite3_stmt *_sql;
    int int_result = sqlite3_prepare_v2(session->db, sql, (int) len, &_sql, NULL);
    assert(int_result == SQLITE_OK);
    if (!(int_result == SQLITE_OK))
        return PEP_UNKNOWN_ERROR;

    int _result = 0;
    int_result = sqlite3_step(_sql);
    assert(int_result == SQLITE_ROW);
    if (int_result == SQLITE_ROW)
        _result = sqlite3_column_int(_sql, 0);
    sqlite3_finalize(_sql);
    if (int_result != SQLITE_ROW)
        return PEP_UNKNOWN_ERROR;

    *result = _result > 0;

    return PEP_STATUS_OK;
}

PEP_STATUS challengeAccepted(PEP_SESSION session, bool *result)
{
    assert(session && result);
    if (!(session && result))
        return PEP_ILLEGAL_VALUE;

    TID_t *t1 = &session->sync_state.keysync.challenge;
    TID_t *t2 = &session->own_sync_state.challenge;

    *result = t1->size == t2->size && memcmp(t1->buf, t2->buf, t1->size) == 0;

    return PEP_STATUS_OK;
}

PEP_STATUS partnerIsGrouped(PEP_SESSION session, bool *result)
{
    assert(session && result);
    if (!(session && result))
        return PEP_ILLEGAL_VALUE;

    *result = session->sync_state.keysync.is_group;

    return PEP_STATUS_OK;
}

PEP_STATUS keyElectionWon(PEP_SESSION session, bool *result)
{
    assert(session && result);
    if (!(session && result))
        return PEP_ILLEGAL_VALUE;

    pEp_identity *from = session->sync_state.basic.from;

    assert(from && from->fpr && from->fpr[0] && from->address && from->address[0]);
    if (!(from && from->fpr && from->fpr[0] && from->address && from->address[0]))
        return PEP_ILLEGAL_VALUE;

    pEp_identity *me = NULL;
    PEP_STATUS status = get_identity(session, from->address, PEP_OWN_USERID, &me);
    assert(status == PEP_STATUS_OK);
    if (status)
        return status;

    assert(me->fpr && me->fpr[0]);
    if (!(me->fpr && me->fpr[0])) {
        free_identity(me);
        return PEP_ILLEGAL_VALUE;
    }

    size_t len = MIN(strlen(from->fpr), strlen(me->fpr));
    *result = strncasecmp(from->fpr, me->fpr, len) > 0;
    free_identity(me);

    return PEP_STATUS_OK;
}

PEP_STATUS closeHandshakeDialog(PEP_SESSION session)
{
    assert(session);
    if (!session)
        return PEP_ILLEGAL_VALUE;

    assert(session->notifyHandshake);
    if (!session->notifyHandshake)
        return PEP_SYNC_NO_NOTIFY_CALLBACK;

    PEP_STATUS status = session->notifyHandshake(
            session->sync_management, NULL, NULL, SYNC_NOTIFY_OVERTAKEN);
    if (status)
        return status;

    return PEP_STATUS_OK;
}

PEP_STATUS openChallenge(PEP_SESSION session)
{
    assert(session);
    if (!session)
        return PEP_ILLEGAL_VALUE;

    pEpUUID c;
    uuid_generate_random(c);

    OCTET_STRING_fromBuf(&session->own_sync_state.challenge, (char *) c, 16);

    return PEP_STATUS_OK;
}

PEP_STATUS storeChallenge(PEP_SESSION session)
{
    assert(session);
    if (!session)
        return PEP_ILLEGAL_VALUE;

    TID_t *src = &session->sync_state.keysync.challenge;
    TID_t *dst = &session->own_sync_state.challenge;

    assert(src->size == 16);
    if (!(src->size == 16))
        return PEP_UNKNOWN_ERROR;

    OCTET_STRING_fromBuf(dst, (char *) src->buf, src->size);

    return PEP_STATUS_OK;
}

PEP_STATUS openTransaction(PEP_SESSION session)
{
    assert(session);
    if (!session)
        return PEP_ILLEGAL_VALUE;

    pEpUUID c;
    uuid_generate_random(c);

    OCTET_STRING_fromBuf(&session->own_sync_state.transaction, (char *) c, 16);

    return PEP_STATUS_OK;
}

PEP_STATUS storeTransaction(PEP_SESSION session)
{
    assert(session);
    if (!session)
        return PEP_ILLEGAL_VALUE;

    TID_t *src = &session->sync_state.keysync.transaction;
    TID_t *dst =  &session->own_sync_state.transaction;

    assert(src->size == 16);
    if (!(src->size == 16))
        return PEP_UNKNOWN_ERROR;

    OCTET_STRING_fromBuf(dst, (char *) src->buf, src->size);

    return PEP_STATUS_OK;
}

PEP_STATUS showSoleHandshake(PEP_SESSION session)
{
    assert(session);
    if (!session)
        return PEP_ILLEGAL_VALUE;

    assert(session->notifyHandshake);
    if (!session->notifyHandshake)
        return PEP_SYNC_NO_NOTIFY_CALLBACK;
 
    assert(session->sync_state.basic.from);
    if (!session->sync_state.basic.from)
        return PEP_ILLEGAL_VALUE;

    pEp_identity *from = session->sync_state.basic.from;
    pEp_identity *me = NULL;
    PEP_STATUS status = get_identity(session, from->address, PEP_OWN_USERID, &me);
    assert(status == PEP_STATUS_OK);
    if (status)
        return status;

    assert(me->fpr && me->fpr[0]);
    if (!(me->fpr && me->fpr[0])) {
        free_identity(me);
        return PEP_ILLEGAL_VALUE;
    }

    pEp_identity *partner = identity_dup(from);
    if (!partner) {
        free_identity(me);
        return PEP_OUT_OF_MEMORY;
    }

    status = session->notifyHandshake(session->sync_management, me,
            partner, SYNC_NOTIFY_INIT_FORM_GROUP);
    if (status)
        return status;

    return PEP_STATUS_OK;
}

PEP_STATUS disable(PEP_SESSION session)
{
    assert(session);
    if (!session)
        return PEP_ILLEGAL_VALUE;


    return PEP_STATUS_OK;
}

PEP_STATUS saveGroupKeys(PEP_SESSION session)
{
    assert(session);
    if (!session)
        return PEP_ILLEGAL_VALUE;

    identity_list *il = IdentityList_to_identity_list(&session->sync_state.keysync.identities, NULL);
    if (!il)
        return PEP_OUT_OF_MEMORY;
    
    // BUG: this should be a transaction and been rolled back completely on error
    for (identity_list *_il = il; _il && _il->ident; _il = _il->next) {
        PEP_STATUS status = set_identity(session, _il->ident);
        if (status) {
            free_identity_list(il);
            return status;
        }
    }

    free_identity_list(il);

    return PEP_STATUS_OK;
}

PEP_STATUS ownKeysAreGroupKeys(PEP_SESSION session)
{
    assert(session);
    if (!session)
        return PEP_ILLEGAL_VALUE;

    static const char *sql = "select fpr, username, comm_type, lang,"
        "   identity.flags | pgp_keypair.flags"
        "   from identity"
        "   join person on id = identity.user_id"
        "   join pgp_keypair on fpr = identity.main_key_id"
        "   join trust on id = trust.user_id"
        "       and pgp_keypair_fpr = identity.main_key_id"
        "   where identity.user_id = '" PEP_OWN_USERID "';";
    static const size_t len = sizeof("select fpr, username, comm_type, lang,"
        "   identity.flags | pgp_keypair.flags"
        "   from identity"
        "   join person on id = identity.user_id"
        "   join pgp_keypair on fpr = identity.main_key_id"
        "   join trust on id = trust.user_id"
        "       and pgp_keypair_fpr = identity.main_key_id"
        "   where identity.user_id = '" PEP_OWN_USERID "';");
    sqlite3_stmt *_sql;
    int int_result = sqlite3_prepare_v2(session->db, sql, (int) len, &_sql, NULL);
    assert(int_result == SQLITE_OK);
    if (!(int_result == SQLITE_OK))
        return PEP_UNKNOWN_ERROR;

    identity_list *il = new_identity_list(NULL);
    if (!il)
        return PEP_OUT_OF_MEMORY;

    pEp_identity *from = session->sync_state.basic.from;
    identity_list *_il = il;

    int result;
    do {
        result = sqlite3_step(_sql);
        pEp_identity *_identity = NULL;
        switch (result) {
        case SQLITE_ROW:
            _identity = new_identity(
                    from->address,
                    (const char *) sqlite3_column_text(_sql, 0),
                    from->user_id,
                    (const char *) sqlite3_column_text(_sql, 1)
                    );
            assert(_identity);
            if (_identity == NULL)
                return PEP_OUT_OF_MEMORY;

            _identity->comm_type = (PEP_comm_type)
                sqlite3_column_int(_sql, 2);
            const char* const _lang = (const char *)
                sqlite3_column_text(_sql, 3);
            if (_lang && _lang[0]) {
                assert(_lang[0] >= 'a' && _lang[0] <= 'z');
                assert(_lang[1] >= 'a' && _lang[1] <= 'z');
                assert(_lang[2] == 0);
                _identity->lang[0] = _lang[0];
                _identity->lang[1] = _lang[1];
                _identity->lang[2] = 0;
            }
            _identity->flags = (unsigned int)
                sqlite3_column_int(_sql, 4);

            _il = identity_list_add(_il, _identity);
            if (!_il) {
                free_identity_list(il);
                free_identity(_identity);
                return PEP_OUT_OF_MEMORY;
            }
            break;

        case SQLITE_DONE:
            break;

        default:
            free_identity_list(il);
            return PEP_UNKNOWN_ERROR;
        }
    } while (result != SQLITE_DONE);

    IdentityList_t *r = IdentityList_from_identity_list(il, &session->sync_state.keysync.identities);
    free_identity_list(il);
    if (!r)
        return PEP_OUT_OF_MEMORY;

    return PEP_STATUS_OK;
}

PEP_STATUS showJoinGroupHandshake(PEP_SESSION session)
{
    assert(session);
    if (!session)
        return PEP_ILLEGAL_VALUE;

    assert(session->notifyHandshake);
    if (!session->notifyHandshake)
        return PEP_SYNC_NO_NOTIFY_CALLBACK;
 
    assert(session->sync_state.basic.from);
    if (!session->sync_state.basic.from)
        return PEP_ILLEGAL_VALUE;

    pEp_identity *from = session->sync_state.basic.from;
    pEp_identity *me = NULL;
    PEP_STATUS status = get_identity(session, from->address, PEP_OWN_USERID, &me);
    assert(status == PEP_STATUS_OK);
    if (status)
        return status;

    assert(me->fpr && me->fpr[0]);
    if (!(me->fpr && me->fpr[0])) {
        free_identity(me);
        return PEP_ILLEGAL_VALUE;
    }

    pEp_identity *partner = identity_dup(from);
    if (!partner) {
        free_identity(me);
        return PEP_OUT_OF_MEMORY;
    }

    status = session->notifyHandshake(session->sync_management, me,
            partner, SYNC_NOTIFY_INIT_ADD_OUR_DEVICE);
    if (status)
        return status;

    return PEP_STATUS_OK;
}

PEP_STATUS showGroupedHandshake(PEP_SESSION session)
{
    assert(session);
    if (!session)
        return PEP_ILLEGAL_VALUE;

    assert(session->notifyHandshake);
    if (!session->notifyHandshake)
        return PEP_SYNC_NO_NOTIFY_CALLBACK;
 
    assert(session->sync_state.basic.from);
    if (!session->sync_state.basic.from)
        return PEP_ILLEGAL_VALUE;

    pEp_identity *from = session->sync_state.basic.from;
    pEp_identity *me = NULL;
    PEP_STATUS status = get_identity(session, from->address, PEP_OWN_USERID, &me);
    assert(status == PEP_STATUS_OK);
    if (status)
        return status;

    assert(me->fpr && me->fpr[0]);
    if (!(me->fpr && me->fpr[0])) {
        free_identity(me);
        return PEP_ILLEGAL_VALUE;
    }

    pEp_identity *partner = identity_dup(from);
    if (!partner) {
        free_identity(me);
        return PEP_OUT_OF_MEMORY;
    }

    status = session->notifyHandshake(session->sync_management, me,
            partner, SYNC_NOTIFY_INIT_ADD_OTHER_DEVICE);
    if (status)
        return status;

    return PEP_STATUS_OK;
}

