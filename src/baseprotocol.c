#include "pEp_internal.h"

PEP_STATUS prepare_message(
        const pEp_identity *me,
        const pEp_identity *partner,
        char *payload,
        size_t size,
        message **result
    )
{
    assert(me);
    assert(partner);
    assert(payload);

    *result = NULL;

    message *msg = new_message(PEP_dir_outgoing);
    if (!msg)
        goto enomem;

    msg->from = identity_dup(me);
    if (!msg->from)
        goto enomem;

    msg->to = new_identity_list(identity_dup(partner));
    if (!msg->to)
        goto enomem;

    msg->shortmsg = strdup("pEp");
    assert(msg->shortmsg);
    if (!msg->shortmsg)
        goto enomem;

    msg->longmsg = strdup("This message is part of p≡p's concept to synchronize.\n\n"
                        "You can safely ignore it. It will be deleted automatically.\n");
    assert(msg->longmsg);
    if (!msg->longmsg)
        goto enomem;

    msg->attachments = new_bloblist(payload, size, "application/pEp", "auto.pEp");
    if (msg->attachments == NULL)
        goto enomem;

    *result = msg;
    return PEP_STATUS_OK;

enomem:
    free_message(msg);
    return PEP_OUT_OF_MEMORY;
}

