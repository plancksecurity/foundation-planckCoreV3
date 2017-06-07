// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "pEp_internal.h"
#include "message_api.h"

PEP_STATUS decorate_message(
        message *msg,
        char *payload,
        size_t size
    )
{
    assert(msg);
    assert(payload);
    assert(size);

    if (!(msg && payload && size))
        return PEP_ILLEGAL_VALUE;

    bloblist_t *bl = bloblist_add(msg->attachments, payload, size,
            "application/pEp.sync", "ignore_this_attachment.pEp", NULL);
    if (bl == NULL)
        goto enomem;

    msg->attachments = bl;
    return PEP_STATUS_OK;

enomem:
    return PEP_OUT_OF_MEMORY;
}

PEP_STATUS prepare_message(
        const pEp_identity *me,
        const pEp_identity *partner,
        char *payload,
        size_t size,
        message **result
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(me);
    assert(partner);
    assert(payload);
    assert(size);
    assert(result);

    if (!(me && partner && payload && size && result))
        return PEP_ILLEGAL_VALUE;

    *result = NULL;

    message *msg = new_message(PEP_dir_outgoing);
    if (!msg)
        goto enomem;

    add_opt_field(msg, "pEp-auto-consume", "yes");

    msg->from = identity_dup(me);
    if (!msg->from)
        goto enomem;

    msg->to = new_identity_list(identity_dup(partner));
    if (!msg->to)
        goto enomem;

    msg->shortmsg = strdup("p≡p synchronization message - please ignore");
    assert(msg->shortmsg);
    if (!msg->shortmsg)
        goto enomem;

    msg->longmsg = strdup("This message is part of p≡p's concept to synchronize.\n\n"
                        "You can safely ignore it. It will be deleted automatically.\n");
    assert(msg->longmsg);
    if (!msg->longmsg)
        goto enomem;

    status = decorate_message(msg, payload, size);
    if (status == PEP_STATUS_OK)
        *result = msg;
    return status;

enomem:
    free_message(msg);
    return PEP_OUT_OF_MEMORY;
}
