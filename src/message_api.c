#include "message_api.h"
#include "keymanagement.h"

#include <libetpan/libetpan.h>
#include <assert.h>
#include <string.h>

PEP_STATUS encrypt_message(
        PEP_SESSION session,
        const message *src,
        stringlist_t * extra,
        message **dst
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);
    assert(src);
    assert(dst);
    *dst = NULL;

    message *msg = new_message(src->dir, src->from, src->to, NULL);
    if (msg == NULL)
        return PEP_OUT_OF_MEMORY;

    src->from->me = true;

    status = myself(session, src->from);
    if (status != PEP_STATUS_OK) {
        free_message(msg);
        return status;
    }

    stringlist_t * keys = new_stringlist(src->from->fpr);
    if (keys == NULL) {
        free_message(msg);
        return PEP_OUT_OF_MEMORY;
    }

    stringlist_t *_x;
    for (_x = extra; _x && _x->value; _x = _x->next) {
        if (stringlist_add(keys, _x->value) == NULL) {
            free_message(msg);
            free_stringlist(keys);
            return PEP_OUT_OF_MEMORY;
        }
    }
    
    identity_list * _il;
    for (_il = src->to; _il && _il->ident; _il = _il->next) {
        status = update_identity(session, _il->ident);
        if (status != PEP_STATUS_OK) {
            free_message(msg);
            free_stringlist(keys);
            return status;
        }
        if (_il->ident->fpr) {
            if (stringlist_add(keys, _il->ident->fpr) == NULL) {
                free_message(msg);
                free_stringlist(keys);
                return PEP_OUT_OF_MEMORY;
            }
        }
        else
            status = PEP_KEY_NOT_FOUND;
    }

    int _own_keys = 1;
    if (extra)
        _own_keys += stringlist_length(extra);
    
    if (stringlist_length(keys) > _own_keys) {
        char *ptext = NULL;
        char *ctext = NULL;
        size_t csize = 0;

        // TODO: set ptext to MIME text

        status = encrypt_and_sign(session, keys, ptext, strlen(ptext), &ctext, &csize);
        if (ctext) {
            msg->longmsg = ctext;
            msg->longmsg_size = csize;
            *dst = msg;
        }
        else
            free_message(msg);
        free(ptext);
    }
    else
        free_message(msg);

    free_stringlist(keys);
    return status;
}

PEP_STATUS decrypt_message(
        PEP_SESSION session,
        const message *src,
        message **dst
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    return status;
}

