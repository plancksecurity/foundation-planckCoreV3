#include "echo_api.h"

#include "pEp_internal.h"
#include "baseprotocol.h"
#include "distribution_codec.h"

/* Return a new Ping message, or NULL on failure. */
static Distribution_t* create_Ping_message(void)
{
    Distribution_t *msg = calloc(sizeof(Distribution_t), 1);
    if (msg == NULL)
        return NULL;
    msg->present = Distribution_PR_echo;
    msg->choice.echo.present = Echo_PR_ping;
    pEpUUID c;
    uuid_generate_random(c);
    int failure = OCTET_STRING_fromBuf(& msg->choice.echo.choice.ping.challenge,
                                       (char *) c, 16);
    if (failure) {
        free(msg);
        return NULL;
    }
    return msg;
}

DYNAMIC_API PEP_STATUS send_ping(PEP_SESSION session,
                                 pEp_identity *from,
                                 pEp_identity *to)
{
    /* Sanity checks. */
    if (! (session && session->messageToSend && from && to))
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS status = PEP_STATUS_OK;
    char *data = NULL;

    /* Craft an attachment. */
    Distribution_t *msg = create_Ping_message ();
    if (msg == NULL)
        return PEP_OUT_OF_MEMORY;

    /* Encode it as an ASN.1 PER, then free the one we built. */
    size_t size;
    status = encode_Distribution_message(msg, &data, &size);
    ASN_STRUCT_FREE(asn_DEF_Distribution, msg); /* free on error as well:
                                                   move sementics */
    if (status != PEP_STATUS_OK)
        return PEP_OUT_OF_MEMORY;

    /* Make a message with the binary attached, as a network-data-structure
       message. */
    message *m = NULL;
    status = base_prepare_message(session, from, to, BASE_DISTRIBUTION,
                                  data, size, NULL, & m);
    if (status != PEP_STATUS_OK) {
        free(data);
        return status;
    }

    /* Send it. */
    status = session->messageToSend(m);
    if (status != PEP_STATUS_OK) {
        free_message(m);
        return status;
    }
    
    return PEP_STATUS_OK;
}
