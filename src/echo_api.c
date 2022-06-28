#include "echo_api.h"

#include "pEp_internal.h"
#include "baseprotocol.h"
#include "distribution_codec.h"

#include "status_to_string.h" // FIXME: remove.

#include <assert.h>


/* Return a new Ping or Pong message, or NULL on failure.  The given uuid is
   used to fill the challenge / response field. */
static Distribution_t* create_Ping_or_Pong_message(const pEpUUID uuid,
                                                   bool ping)
{
    Distribution_t *msg = calloc(sizeof(Distribution_t), 1);
    if (msg == NULL || uuid == NULL)
        return NULL;
    msg->present = Distribution_PR_echo;
    int failure;
    if (ping) {
        msg->choice.echo.present = Echo_PR_ping;
        failure = OCTET_STRING_fromBuf(& msg->choice.echo.choice.ping.challenge,
                                       (char *) uuid, 16);
    }
    else {
        msg->choice.echo.present = Echo_PR_pong;
        failure = OCTET_STRING_fromBuf(& msg->choice.echo.choice.pong.challenge,
                                       (char *) uuid, 16);
    }
    if (failure) {
        free(msg);
        return NULL;
    }
    return msg;
}

/* A helper factoring the common code in send_ping and send_pong.
   The Boolean flag determines what kind of message is sent.  The uuid field
   is used for challenge / response. */
static PEP_STATUS send_ping_or_pong(PEP_SESSION session,
                                    const pEp_identity *from,
                                    const pEp_identity *to,
                                    const pEpUUID uuid,
                                    bool ping)
{
    /* Sanity checks. */
    if (! (session && session->messageToSend && from && to))
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS status = PEP_STATUS_OK;
    char *data = NULL;

    /* Craft an attachment. */
    Distribution_t *msg = create_Ping_or_Pong_message(uuid, ping);
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
    message *non_encrypted_m = NULL;
    status = base_prepare_message(session, from, to, BASE_DISTRIBUTION,
                                  data, size, NULL, & non_encrypted_m);
    if (status != PEP_STATUS_OK) {
        free(data);
        return status;
    }

    /* "Encrypt" the message in the sense of calling encrypt_message; this, in
       case we have no key for the recipient, as it will often happen with Ping
       messages, will alter the message to contain the sender's key... */
    message *m = NULL;
    status = encrypt_message(session, non_encrypted_m, NULL, &m,
                             PEP_enc_PEP, PEP_encrypt_flag_default);
    fprintf(stderr, "DEBUG send_ping_or_pong after encrypting: status %i (%s)\n", status, pEp_status_to_string(status));
    if (status == PEP_STATUS_OK)
        free_message(non_encrypted_m);
    else if (status == PEP_UNENCRYPTED)
        m = non_encrypted_m;
    else {
        free_message(non_encrypted_m);
        fprintf(stderr, "DEBUG send_ping_or_pong, not supposed to happen: "
                "status %i (%s)\n", status, pEp_status_to_string(status));
        return status;
    }
    /* ...a Pong message should actually always be encrypted. */
    
    /* Send it. */
    status = session->messageToSend(m);
    if (status != PEP_STATUS_OK) {
        free_message(m);
        return status;
    }
    /* We must *not* free the message in case of success: the called function
       gets ownership of it. */

    return PEP_STATUS_OK;
}

DYNAMIC_API PEP_STATUS send_ping(PEP_SESSION session,
                                 const pEp_identity *from,
                                 const pEp_identity *to)
{
    pEpUUID challenge;
    uuid_generate_random(challenge);
    return send_ping_or_pong(session, from, to, challenge, true);
}

PEP_STATUS send_pong(PEP_SESSION session,
                     message *ping_message) {
    /* Argument checks.  No need to check for messageToSend here, since we
       will check later when actually sending. */
    assert (session && ping_message);
    if (! (session && ping_message))
        return PEP_ILLEGAL_VALUE;
    /* Sanity check. */
    if (ping_message->dir != PEP_dir_incoming)
        return PEP_ILLEGAL_VALUE;
    if (identity_list_length(ping_message->to) != 1)
        return PEP_ILLEGAL_VALUE;
    if (identity_list_length(ping_message->cc) != 0)
        return PEP_ILLEGAL_VALUE;
    if (identity_list_length(ping_message->bcc) != 0)
        return PEP_ILLEGAL_VALUE;
    if (bloblist_length(ping_message->attachments) != 1)
        return PEP_ILLEGAL_VALUE;
    
    /* Extract identities from the message envelope. */
    pEp_identity *ping_from = ping_message->from;
    pEp_identity *ping_to = ping_message->to->ident;
    /* Decode the ping message into an ASN.1 PER message, and the ASN.1 PER
       message into a Distribution_t message; extract the fields we need;
       send the message.  Free. */
    char *data = ping_message->attachments->value;
    size_t data_size = ping_message->attachments->size;
    Distribution_t *asn1_message;
    PEP_STATUS status = decode_Distribution_message(data, data_size,
                                                    &asn1_message);
    if (status != PEP_STATUS_OK)
        return status;
    if (asn1_message->choice.echo.choice.ping.challenge.size != 16) // just for internal consistency: turn it into an assert
        return PEP_ILLEGAL_VALUE;
    if (asn1_message->choice.echo.present != Echo_PR_ping)
        return PEP_ILLEGAL_VALUE;

    pEpUUID response;
    strncpy(response, asn1_message->choice.echo.choice.ping.challenge.buf, 16);
    // Notice that in the Pong message the From and To fields from the Ping
    // message are reversed.
    status = send_ping_or_pong(session,
                               ping_to,
                               ping_from,
                               response,
                               false);
    if (status == PEP_STATUS_OK)
        free_message(ping_message);
    ASN_STRUCT_FREE(asn_DEF_Distribution, asn1_message);
    return status;
}
