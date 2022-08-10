#include "echo_api.h"

#include "pEp_internal.h"
#include "baseprotocol.h"
#include "distribution_codec.h"

#include <assert.h>
#include <sqlite3.h>

#include "status_to_string.h" // FIXME: remove.


/* Debugging.
 * ***************************************************************** */

#define DEBUG_ECHO

#if ! defined(DEBUG_ECHO)
# define echo_log(stream, ...)               \
    do { /* Do nothing. */ } while (false)
# else
# define echo_log fprintf
#endif


/* Challenge/response handling
 * ***************************************************************** */

PEP_STATUS upgrade_add_echo_challange_field(PEP_SESSION session) {
    int int_result
        = sqlite3_exec(session->db,
                       "ALTER TABLE Identity ADD COLUMN echo_challenge BLOB;\n"
                       , NULL, NULL, NULL);

    switch (int_result) {
    case SQLITE_OK:
        /* Upgrading was successful. */
        return PEP_STATUS_OK;
    case SQLITE_ERROR:
        /* Upgrading was not needed, but this is not a problem: the column
           we want to add exists. */
        return PEP_STATUS_OK;
    default:
        /* An actual unforeseen error. */
        return PEP_UNKNOWN_DB_ERROR;
    }
}

/**
 *  <!--       echo_challenge_for_identity()       -->
 *
 *  @brief Retrieve the stored challenge for the given identity; if
 *         the identity has no stored challenge write a new one first.
 *         This is inteded for use when:
 *         (1) preparing a challenge for an outgoing Ping message;
 *         (2) checking that an incoming Pong message has the repsonse
 *             we expect.
 *
 *  @param[in]   session             session
 *  @param[in]   identity            the identity we are dealing with
 *  @param[out]  challenge           ownership remains to the caller.
 *                                   Only meaningful on success.
 *
 *  @retval PEP_STATUS_OK            success
 *  @retval PEP_UNKNOWN_DB_ERROR     unforeseen database error
 *
 */
static PEP_STATUS echo_challenge_for_identity(PEP_SESSION session,
                                              const pEp_identity *identity,
                                              pEpUUID challenge)
{
    /* Sanity checks. */
    assert(session && identity && challenge);
    if (! (session && identity && challenge))
        return PEP_ILLEGAL_VALUE;

    /* Define a macro used everywhere with the SQL api below. */
    PEP_STATUS status = PEP_STATUS_OK;
    int sql_status;
#define ON_SQL_ERROR_SET_STATUS_AND_GOTO    \
    do {                                    \
        if (sql_status != SQLITE_OK         \
            && sql_status != SQLITE_DONE    \
            && sql_status != SQLITE_ROW) {  \
            status = PEP_UNKNOWN_DB_ERROR;  \
            goto end;                       \
        }                                   \
    } while (false)

    /* Look at the database.  First check if we have a stored challenge... */
    sqlite3_stmt *select_statement = NULL;
    sqlite3_stmt *update_statement = NULL;
    sql_status = sqlite3_prepare_v2(session->db,
                                    " SELECT echo_challenge "
                                    " FROM Identity I "
                                    " WHERE I.address = ?1 "
                                    "       AND I.user_id = ?2; "
                                    , -1, &select_statement, NULL);
    ON_SQL_ERROR_SET_STATUS_AND_GOTO;
    reset_and_clear_bindings(select_statement);
    sql_status = sqlite3_bind_text(select_statement, 1, identity->address, -1, SQLITE_STATIC);
    ON_SQL_ERROR_SET_STATUS_AND_GOTO;
    sql_status = sqlite3_bind_text(select_statement, 2, identity->user_id, -1, SQLITE_STATIC);
    ON_SQL_ERROR_SET_STATUS_AND_GOTO;
    sql_status = sqlite3_step(select_statement);
    ON_SQL_ERROR_SET_STATUS_AND_GOTO;
    const void *stored_challenge;
    if (sql_status != SQLITE_ROW) {
        /* The identity is not in the database yet: make sure it is there before
           we alter the row in order to set its challenge field.

           positron, 2022-07: I used to use set_identity instead of
           update_identity on a copy, but that led to PEP_ILLEGAL_VALUE status.
           This way I am making sure that the identity is valid, in some sense
           of which the details still escape me. */
        pEp_identity *identity_copy = identity_dup(identity);
        if (identity_copy == NULL) {
            status = PEP_OUT_OF_MEMORY;
            goto end;
        }
        status = update_identity(session, identity_copy);
        if (status != PEP_STATUS_OK) {
            free_identity(identity_copy);
            goto end;
        }
        free_identity(identity_copy);
        stored_challenge = NULL;
    }
    else if (sqlite3_column_type(select_statement, 0) == SQLITE_NULL)
        stored_challenge = NULL;
    else
        stored_challenge = sqlite3_column_blob(select_statement, 0);
    if (stored_challenge != NULL) {
        memcpy(challenge, stored_challenge, sizeof(pEpUUID));
        goto end;
    }

    /* If we are here then we have no stored challenge.  Make a new one... */
    uuid_generate_random(challenge);
    /* These crude alternatives are convenient for debugging: */
//challenge[sizeof(pEpUUID) - 1] = '\0';
//sprintf(challenge, "to-%s-%i", getenv("USER"), rand() % (1 << 15));

    /* ...and store it into the database. */
    /* sql_status = sqlite3_exec(session->db, */
    /*                           "BEGIN TRANSACTION; ", NULL, NULL, NULL); */
    /* ON_SQL_ERROR_SET_STATUS_AND_GOTO; */
    sql_status = sqlite3_prepare_v2(session->db,
                                    " UPDATE Identity "
                                    " SET echo_challenge = ?1 "
                                    " WHERE address = ?2 "
                                    "       AND user_id = ?3; "
                                    , -1, &update_statement, NULL);
    ON_SQL_ERROR_SET_STATUS_AND_GOTO;
    reset_and_clear_bindings(update_statement);
    sql_status
        = sqlite3_bind_blob(update_statement, 1, challenge, sizeof(pEpUUID),
                            SQLITE_STATIC);
    ON_SQL_ERROR_SET_STATUS_AND_GOTO;
    sql_status
        = sqlite3_bind_text(update_statement, 2, identity->address, -1,
                            SQLITE_STATIC);
    ON_SQL_ERROR_SET_STATUS_AND_GOTO;
    sql_status
        = sqlite3_bind_text(update_statement, 3, identity->user_id, -1,
                            SQLITE_STATIC);
    ON_SQL_ERROR_SET_STATUS_AND_GOTO;
    sql_status = sqlite3_step(update_statement);
    ON_SQL_ERROR_SET_STATUS_AND_GOTO;
    /* If we arrived here then the SQL UPDATE statement succeeded. */

 end:
    sqlite3_finalize(select_statement);
    sqlite3_finalize(update_statement);
    return status;
}

PEP_STATUS check_pong_challenge(PEP_SESSION session,
                                const pEp_identity *identity,
                                const Distribution_t *pong_distribution_message)
{
    /* Sanity checks. */
    if (! (session && identity && pong_distribution_message))
        return PEP_ILLEGAL_VALUE;
    if (pong_distribution_message->present != Distribution_PR_echo)
        return PEP_ILLEGAL_VALUE;
    if (pong_distribution_message->choice.echo.present != Echo_PR_echoPong)
        return PEP_ILLEGAL_VALUE; /* We handle Pong, not Ping. */

    /* Retrieve the two values. */
    PEP_STATUS status = PEP_STATUS_OK;
    pEpUUID expected_response;
    status = echo_challenge_for_identity(session, identity, expected_response);
    if (status != PEP_STATUS_OK)
        return status;
    pEpUUID actual_response; /* I am not completely sure about how the type is
                                defined on windows: make this robust at the cost
                                of one more copy. */
    memcpy(actual_response,
           pong_distribution_message->choice.echo.choice.echoPong.challenge.buf,
           pong_distribution_message->choice.echo.choice.echoPong.challenge.size);

    /* Compare. */
    if (memcmp(actual_response, expected_response, sizeof(pEpUUID)))
        return PEP_ILLEGAL_VALUE;
    else
        return PEP_STATUS_OK;
}


/* Echo messages
 * ***************************************************************** */

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
        msg->choice.echo.present = Echo_PR_echoPing;
        failure = OCTET_STRING_fromBuf(& msg->choice.echo.choice.echoPing.challenge,
                                       (char *) uuid, 16);
    }
    else {
        msg->choice.echo.present = Echo_PR_echoPong;
        failure = OCTET_STRING_fromBuf(& msg->choice.echo.choice.echoPong.challenge,
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

    /*if (! session->enable_echo_protocol)*/ {
        fprintf(stderr,  "* Echo protocol disabled: not sending a %s to %s <%s>\n", (ping ? "Ping" : "Pong"), (to->username ? to->username : "<no username>"), (to->address ? to->address : "<no address>"));
        return PEP_STATUS_OK;
    }

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
       case we have no key for the recipient, as it will normally happen with
       Ping messages, will alter the message to contain the sender's key. */
    message *m = NULL;
    status = encrypt_message(session, non_encrypted_m, NULL, &m,
                             PEP_enc_PEP, PEP_encrypt_flag_default);
    echo_log(stderr, "  send %s from %s <%s> to %s <%s>, status after encrypting %i %s\n", (ping ? "Ping" : "Pong"), from->username, from->address, to->username, to->address, status, pEp_status_to_string(status));
    if (status == PEP_STATUS_OK)
        free_message(non_encrypted_m);
    else if (status == PEP_UNENCRYPTED)
        m = non_encrypted_m;
    else {
        free_message(non_encrypted_m);
        /* Differently from a status of PEP_UNENCRYPTED this is an actual
           unexpected error, to be reported to the caller. */
        return status;
    }

    /* Send it. */
    status = session->messageToSend(m);
    if (status != PEP_STATUS_OK) {
        free_message(m);
        return status;
    }

    /* In case of success we must *not* free the message: the called function
       gets ownership of it. */
    return PEP_STATUS_OK;
}

DYNAMIC_API PEP_STATUS send_ping(PEP_SESSION session,
                                 const pEp_identity *from,
                                 const pEp_identity *to)
{
    pEpUUID challenge;
    PEP_STATUS status = echo_challenge_for_identity(session, to, challenge);
    if (status != PEP_STATUS_OK)
        return status;
    else
        return send_ping_or_pong(session, from, to, challenge, true);
}

PEP_STATUS send_pong(PEP_SESSION session,
                     const message *ping_message,
                     const Distribution_t *ping_distribution_message) {
    /* Argument checks.  No need to check for messageToSend here, since we
       will check later when actually sending. */
    assert(session && ping_message && ping_distribution_message);
    if (! (session && ping_message && ping_distribution_message))
        return PEP_ILLEGAL_VALUE;
    /* Sanity checks. */
    if (ping_message->dir != PEP_dir_incoming)
        return PEP_ILLEGAL_VALUE;
    if (ping_message->recv_by == NULL)
        return PEP_ILLEGAL_VALUE;
    if (! ping_message->recv_by->me)
        return PEP_ILLEGAL_VALUE;
    if (ping_distribution_message->present != Distribution_PR_echo)
        return PEP_ILLEGAL_VALUE;
    if (ping_distribution_message->choice.echo.present != Echo_PR_echoPing)
        return PEP_ILLEGAL_VALUE; /* We reply to Ping, not to Pong. */

    /* About identities, the To and From fields must be swapped between ping and
       pong.  In particular we have that  pong.from = ping.recv_by
                                and that  pong.to   = ping.from .
       About the challenge, we simply reuse the challenge allocated string
       as a response. */
    const pEp_identity *pong_from = ping_message->recv_by;
    if (! pong_from->me)
        return PEP_ILLEGAL_VALUE;
    const pEp_identity *pong_to = ping_message->from;
    const unsigned char *response
        = ping_distribution_message->choice.echo.choice.echoPing.challenge.buf;

    return send_ping_or_pong(session,
                             pong_from,
                             pong_to,
                             response,
                             false);
}


/* Policy
 * ***************************************************************** */

/* The functions in this section serve to implement some policy using the
   Distribution.Echo protocol.

   Properly handling failure in a situation where we send multiple messages
   to multiple recipients over an unreliable protocol seems futile; I have
   avoided complicated status code returns. */

/* Return true iff the given identity is known, in the sense that we do have at
   leat a key for it.  In case of error consider the identity as known, which
   will avoid a Ping. */
static bool identity_known(PEP_SESSION session,
                           const pEp_identity *identity)
{
    bool result = true;
    stringlist_t *keys = NULL;
    if (identity->me)
        return true;
    pEp_identity *identity_copy = identity_dup(identity);
    if (identity_copy == NULL)
        goto end;
    PEP_STATUS status;
    status = update_identity (session, identity_copy);
    if (status != PEP_STATUS_OK) {
        echo_log(stderr, "identity_known: update_identity failed on %s <%s>\n", identity->username, identity->address);
        goto end;
    }
    status = get_all_keys_for_identity(session, identity_copy, &keys);
    if (status == PEP_KEY_NOT_FOUND)
        result = false;
    else if (status == PEP_STATUS_OK)
        result = (keys != NULL); /* I could say have written "result = true;"
                                    but I am not fond as PEP_KEY_NOT_FOUND as a
                                    status in this case, and this code will
                                    break if the status is removed later. */
    else /* An actual error. */
        goto end;

 end:
    free_identity(identity_copy);
    free_stringlist(keys);
    return result;
}

/* A helper for send_ping_if_unknown.  In case of failure just return false */
PEP_STATUS identity_known_to_use_pEp(PEP_SESSION session,
                                     const pEp_identity *identity,
                                     bool *known_to_use_pEp)
{
    /* Sanity checks. */
    assert(session && identity && known_to_use_pEp);
    if (! (session && identity && known_to_use_pEp))
        return PEP_ILLEGAL_VALUE;

    bool result = false;
    PEP_STATUS status = PEP_STATUS_OK;
    pEp_identity *identity_copy = NULL;
    /* Easy case: an own identity. */
    if (identity->me) {
        result = true;
        goto end;
    }
        
    /* We have to call update_identity on (a copy of) the identity: this will
       make sure that we see the major_ver field set correctly, possibly because
       of a media key. */
    identity_copy = identity_dup(identity);
    if (identity_copy == NULL) {
        status = PEP_OUT_OF_MEMORY;
        goto end;
    }
    status = update_identity(session, identity_copy);
    if (status != PEP_STATUS_OK)
        goto end;
    result = (identity_copy->major_ver > 0);

 end:
    * known_to_use_pEp = result;
    free_identity (identity_copy);
    return status;
}

/* Send a Distribution.Ping message from the identity to the to identity, if we
   do not have a key for the to identity and the identity is not own; do nothing
   otherwise.  Ignore failures.  The to identity is allowed to be NULL.
   Iff only_if_pEp is true, do not send Ping messages to identities not known
   to use pEp. */
static void send_ping_if_unknown(PEP_SESSION session,
                                 const pEp_identity *from_identity,
                                 const pEp_identity *to_identity,
                                 bool only_if_pEp)
{
    assert(session && from_identity);
    if (! (session && from_identity))
        return;
    if (! from_identity->me) {
        echo_log(stderr, "send_ping_if_unknown: trying to send from non-own identity %s <%s>\n", from_identity->username, from_identity->address);
        return;
    }

    /* The To identity is allowed to be NULL, but in that case we do nothing.
       Own identities are dealt with in identity_known . */
    if (to_identity == NULL)
        return;

    /* In case the identity is unknown we may want to ping it... */
    if (! identity_known(session, to_identity))
        {
            /* ...As long as it uses pEp, or we do not care whether it does. */
            if (! only_if_pEp)
                send_ping(session, from_identity, to_identity);
            else {
                bool known_to_use_pEp;
                PEP_STATUS status = identity_known_to_use_pEp (session, to_identity,
                                                               & known_to_use_pEp);
                if (status != PEP_STATUS_OK)
                    return;
                if (known_to_use_pEp)
                    send_ping(session, from_identity, to_identity);
            }
        }
}

/* Send a Distribution.Ping message from the from identity to every identity in
   the to list which has no known key.  Ignore failures.  If only_pEp is true
   ignore identities not known to use pEp. */
static void send_ping_to_unknowns_in(PEP_SESSION session,
                                     const pEp_identity *from_identity,
                                     const identity_list *to_identities,
                                     bool only_pEp)
{
    const identity_list *rest;
    for (rest = to_identities; rest != NULL; rest = rest->next)
        send_ping_if_unknown(session, from_identity, rest->ident, only_pEp);
}

/* This factors the common logic of
   send_ping_to_all_unknowns_in_incoming_message and
   send_ping_to_unknown_pEp_identities_in_incoming_message . */
static PEP_STATUS send_ping_to_unknowns_in_incoming_message(PEP_SESSION session,
                                                            const message *msg,
                                                            bool only_pEp)
{
    /* Sanity checks. */
    assert(session && msg);
    if (! (session && msg))
        return PEP_ILLEGAL_VALUE;
    if (msg->dir == PEP_dir_outgoing)
        fprintf(stderr, "FOO: %s is outgoing\n", msg->shortmsg);
    else
        fprintf(stderr, "FOO: %s is incoming\n", msg->shortmsg);

    if (msg->dir != PEP_dir_incoming)
        return PEP_ILLEGAL_VALUE;

    /* Find the identity who received the message and should send Pings. */
    const pEp_identity *ping_from_identity = msg->recv_by;
    if (msg->recv_by == NULL) {
        /* Applications are supposed never to let this happen, but in practice
           it is difficult to find a reasonable value for messages received as
           Bcc. */
        fprintf(stderr, "APPLICATION BUG: message %s \"%s\" has no Recv-By\n", msg->id, msg->shortmsg ? msg->shortmsg : "<no subject>");
        return PEP_ILLEGAL_VALUE;
    }

    /* Send Pings.  It is harmless to consider our own identities as well as
       potential Ping recipients: those will simply never be sent to, as they
       will all have a known key.  Here we do not make any effort to avoid
       sending multiple Ping messages to the same recipient. */
    send_ping_to_unknowns_in(session, ping_from_identity, msg->to, only_pEp);
    send_ping_to_unknowns_in(session, ping_from_identity, msg->cc, only_pEp);
    send_ping_to_unknowns_in(session, ping_from_identity, msg->reply_to,
                             only_pEp);
    /* Do not consider Bcc identities; the Bcc field should be empty anyway,
       and sending Pings would leak privacy. */
    return PEP_STATUS_OK;
}

PEP_STATUS send_ping_to_all_unknowns_in_incoming_message(PEP_SESSION session,
                                                         const message *msg)
{
    echo_log(stderr, "send_ping_to_all_unknowns_in_incoming_message\n");
    return send_ping_to_unknowns_in_incoming_message (session, msg, false);
}

PEP_STATUS send_ping_to_unknown_pEp_identities_in_incoming_message(PEP_SESSION session,
                                                                   const message *msg)
{
    echo_log(stderr, "send_ping_to_unknown_pEp_identities_in_incoming_message\n");
    return send_ping_to_unknowns_in_incoming_message (session, msg, true);
}
