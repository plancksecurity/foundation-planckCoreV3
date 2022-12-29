/**
 * @file     mixnet.c
 * @brief    Onion-routing and mixnet for pEp
 * @license  GNU General Public License 3.0 - see LICENSE.txt
 */

#include "pEp_internal.h"
#include "message_api.h"
#include "pEpEngine.h"

#include "mixnet.h"

/* Here we need to translate between our internal representation and ASN.1 . */
#include "map_asn1.h"
#include "message_codec.h"


#define ONION_DEBUG_SERIALIZE_TO_XER  1
#define ONION_DEBUG_ENCRYPT           1


/* Message serialisation and deserialisation.
 * ***************************************************************** */

/* Turn the given message into a compact in-memory representation using ASN.1. */
PEP_STATUS onion_serialize_message(PEP_SESSION session,
                                   message *in,
                                   char **encoded_p,
                                   size_t *encoded_size_in_bytes_p)
{
    PEP_REQUIRE(session && in && encoded_p && encoded_size_in_bytes_p);

    /* First initialise output parameters, for defeniveness's sake. */
    * encoded_p = NULL;
    * encoded_size_in_bytes_p = 0;

    /* Initialise data to be freed at the end. */
    PEP_STATUS status = PEP_STATUS_OK;
    ASN1Message_t *in_as_ASN1Message_t = NULL;
    char *encoded = NULL;
    size_t encoded_size_in_bytes;

    /* Perform the actual conversion: from the pEp internal representation
       to the ASN.1 struct in memory, and from that to PER. */
    in_as_ASN1Message_t = ASN1Message_from_message(in, NULL, true, 0);
    if (in_as_ASN1Message_t == NULL) {
        status = PEP_OUT_OF_MEMORY;
        goto end;
    }
    status = encode_ASN1Message_message(in_as_ASN1Message_t, & encoded, & encoded_size_in_bytes);
    if (status != PEP_STATUS_OK)
        goto end;

#if defined(ONION_DEBUG_SERIALIZE_TO_XER)
    // test: switch to XER, for debugging.
    char *encoded_per = encoded;
    char *encoded_xer = NULL;
    status = PER_to_XER_ASN1Message_msg(encoded_per, encoded_size_in_bytes,
                                        & encoded_xer);
    if (status != PEP_STATUS_OK) {
        status = PEP_OUT_OF_MEMORY;
        goto end;
    }
    free(encoded_per);
    encoded = encoded_xer;
    encoded_size_in_bytes = strlen(encoded_xer);
    LOG_TRACE("encoded message as XML: %s", encoded);
#endif

 end:
    /* Free temporary data structures we need to free in every case, error or
       not. */
    ASN_STRUCT_FREE(asn_DEF_ASN1Message, in_as_ASN1Message_t);

    LOG_NONOK_STATUS_NONOK;
    if (status == PEP_STATUS_OK) {
        * encoded_p = encoded;
        * encoded_size_in_bytes_p = encoded_size_in_bytes;
    }
    else
        free(encoded);
    return status;
}

/* Turn the given in-memory ASN.1 object into a pEp message. */
PEP_STATUS onion_deserialize_message(PEP_SESSION session,
                                     const char *encoded,
                                     size_t encoded_size_in_bytes,
                                     message **out_p)
{
    PEP_REQUIRE(session && encoded && encoded_size_in_bytes > 0
                && out_p);

    /* First initialise output parameters, for defeniveness's sake. */
    * out_p = NULL;

    /* Initialise data to be freed at the end. */
    PEP_STATUS status = PEP_STATUS_OK;
    message *out = NULL;
    ASN1Message_t *as_ASN1Message_t = NULL;

    /* Perform the actual conversion: from PER to the in-memory ASN.1 struct,
       and from that to the internal pEp representation. */
#if defined(ONION_DEBUG_SERIALIZE_TO_XER)
    const char *encoded_xer = encoded;
    char *encoded_per = NULL;
    size_t encoded_per_size_in_bytes;
    status = XER_to_PER_ASN1Message_msg(encoded_xer, & encoded_per,
                                        & encoded_per_size_in_bytes);
    if (status != PEP_STATUS_OK)
        goto end;
    encoded = encoded_per;
    encoded_size_in_bytes = encoded_per_size_in_bytes;
#endif
    status = decode_ASN1Message_message(encoded, encoded_size_in_bytes,
                                        & as_ASN1Message_t);
#if defined(ONION_DEBUG_SERIALIZE_TO_XER)
    free(encoded_per);
#endif
    if (status != PEP_STATUS_OK)
        goto end;
    out = ASN1Message_to_message(as_ASN1Message_t, NULL, true, 0);
    if (out == NULL) {
        status = PEP_OUT_OF_MEMORY;
        goto end;
    }

 end:
    /* Free temporary data structures we need to free in every case, error or
       not. */
    ASN_STRUCT_FREE(asn_DEF_ASN1Message, as_ASN1Message_t);

    LOG_NONOK_STATUS_NONOK;
    if (status == PEP_STATUS_OK)
        * out_p = out;
    else
        free(out);
    return status;
}


/* Search for onion identities.
 * ***************************************************************** */

/* The implementation of this is in fact completely separate from the rest of
   onion-routing: this is an SQL exercise. */

DYNAMIC_API PEP_STATUS get_onion_identities(
        PEP_SESSION session,
        size_t trusted_identity_no,
        size_t total_identity_no,
        identity_list **identities)
{
    PEP_REQUIRE(session && identities
                && trusted_identity_no <= total_identity_no);

#define FAIL(pepstatus)        \
    do {                       \
        status = (pepstatus);  \
        goto end;              \
    } while (false)
#define CHECK_SQL_STATUS                                          \
    do {                                                          \
        if (sql_status != SQLITE_OK && sql_status != SQLITE_DONE  \
            && sql_status != SQLITE_ROW) {                        \
            FAIL(PEP_UNKNOWN_DB_ERROR);                           \
        }                                                         \
    } while (false)

    /* Defensiveness: initialise the output to a sensible value before doing
       anything, and work with automatic variables instead of affecting the
       caller's memory. */
    PEP_STATUS status = PEP_STATUS_OK;
    * identities = NULL;
    identity_list *res = NULL;
    size_t found_identity_no = 0;

    /* Run the complicated SQL query returning our identities. */
    int sql_status = SQLITE_OK;
    sql_reset_and_clear_bindings(session->get_onion_identities);
    sqlite3_bind_int(session->get_onion_identities, 1, trusted_identity_no);
    sqlite3_bind_int(session->get_onion_identities, 2, total_identity_no);
    sqlite3_bind_int(session->get_onion_identities, 3, 0/*PEP_ct_pEp_unconfirmed*/);

    /* Keep reading one more line as long as we have not enough rows. */
    while (found_identity_no < total_identity_no) {
        /* Step. */
        sql_status = pEp_sqlite3_step_nonbusy(session, session->get_onion_identities);
        CHECK_SQL_STATUS;
        if (sql_status == SQLITE_DONE)
            FAIL(PEP_CANNOT_FIND_IDENTITY); /* Not enough rows. */

        /* Bind columns into local variables.  These char* variables are only
           bound here, and their memory is handled here.  It is difficult to
           unconditionally free at the end of the function because of sharing:
           strings are shared with the identity, which is shared with the
           list. */
        char *user_id
            = strdup((char *)
                     sqlite3_column_text(session->get_onion_identities, 0));
        if (user_id == NULL)
            FAIL(PEP_OUT_OF_MEMORY);
        char *address
            = strdup((char *)
                     sqlite3_column_text(session->get_onion_identities, 1));;
        if (address == NULL) {
            free(user_id);
            FAIL(PEP_OUT_OF_MEMORY);
        }
        bool trusted;
        trusted = sqlite3_column_int(session->get_onion_identities, 2);
        LOG_TRACE("# found %s %s", user_id,
                  (trusted ? "TRUSTED" : "NOT as trusted (even if it may be)"));

        /* Make an identity data structure, and update it to fill in whatever
           field this query did not fill. */
        pEp_identity *identity = new_identity(address, NULL, user_id, NULL);
        if (identity == NULL) {
            free(user_id);
            free(address);
            FAIL(PEP_OUT_OF_MEMORY);
        }
        status = update_identity(session, identity);
        if (status != PEP_STATUS_OK) {
            free_identity(identity);
            goto end;
        }

        /* Attach the identity to the list.  Notice that the identity is
           shared with the list. */
        identity_list *new_last = identity_list_add(res, identity);
        if (new_last == NULL) {
            free_identity(identity);
            FAIL(PEP_OUT_OF_MEMORY);
        }
        if (res == NULL)
            res = new_last;

        /* End of the iteration: we have found an identity. */
        found_identity_no ++;
    }

 end:
    LOG_TRACE("found %i identities", (int) found_identity_no);
    sql_reset_and_clear_bindings(session->get_onion_identities);
    if (status != PEP_STATUS_OK) {
        free_identity_list(res);
    }
    else
        * identities = res; /* Make the result visible to the caller. */
    LOG_NONOK_STATUS_NONOK;
    return status;
#undef CHECK_SQL_STATUS
#undef FAIL
}


/* Onion routing.
 * ***************************************************************** */

static PEP_STATUS _onion_add_layer(PEP_SESSION session,
                                   message *in,
                                   stringlist_t *extra,
                                   message **out_p,
                                   PEP_enc_format enc_format,
                                   PEP_encrypt_flags_t flags,
                                   pEp_identity *from, pEp_identity *to,
                                   bool innermost)
{
    PEP_REQUIRE(session && in && in->dir == PEP_dir_outgoing && out_p
                && from && to);
    PEP_STATUS status = PEP_STATUS_OK;

    LOG_TRACE("* innermost: %s.  %s <%s>  ->  %s <%s>", (innermost ? "yes" : "no"), from->username, from->address, to->username, to->address);

    /* Initialise the output parameter, for defensiveness's sake.  We will only
       set the actual pointer to a non-NULL value at the end, on success. */
    * out_p = NULL;

    /* Initialise each local variable so that in case of error we can free them
       all. */
    message *res = NULL;
    pEp_identity *from_copy = NULL;
    identity_list *tos_copy = NULL;
    char *shortmsg = NULL;
    char *longmsg = NULL;
    char *encoded_message = NULL;
    size_t encoded_message_length = 0;

    if (innermost) {
        /* This is just an ordinary message. */
        /*
        status
            = encrypt_message_possibly_with_media_key(session, in, extra, &res,
                                                      enc_format, flags, NULL);
        LOG_NONOK_STATUS_NONOK;
        if (status != PEP_STATUS_OK)
            goto end;
            */
        // FIXME: a test.  Of course I want it encrypted.
        res = message_dup(in);
    }
    else {
        /* Allocate message components, then the message itself.  In case of
           any allocation error go to the end, where we free every non-NULL
           thing unconditionally. */
        from_copy = identity_dup(from);
        tos_copy = identity_list_cons_copy(to, NULL);
        shortmsg = strdup("🧅");
        longmsg = strdup("This is an onion-routed message.\n"
                         "Please decode the attachment and pass it along.\n");
        res = new_message(PEP_dir_outgoing);
        if (from_copy == NULL || tos_copy == NULL || shortmsg == NULL
            || longmsg == NULL
            || res == NULL) {
            status = PEP_OUT_OF_MEMORY;
            goto end;
        }
        /* Fill message fields, and set the local variables holding copies of
           message heap-allocated fields to NULL, so that we can free the local
           variables unconditionally at the end.  */
        add_opt_field(res, "X-pEp-onion", "yes");
        res->from = from_copy;
        res->to = tos_copy;
        res->shortmsg = shortmsg;
        res->longmsg = longmsg;
        from_copy = NULL;
        tos_copy = NULL;
        shortmsg = NULL;
        longmsg = NULL;

        /* Add the "in" message to res as an attachment. */
        status = onion_serialize_message(session, in, & encoded_message,
                                         & encoded_message_length);
        if (status != PEP_STATUS_OK) {
            status = PEP_OUT_OF_MEMORY;
            goto end;
        }
        //// // FIXME: delete this test.
        {
            message *another = NULL;
            status = onion_deserialize_message(session, encoded_message,
                                               encoded_message_length,
                                               & another);
            PEP_ASSERT(status == PEP_STATUS_OK);
            free_message(another);
        }
        ////
        bloblist_t *added_bloblist = new_bloblist(encoded_message,
                                                  encoded_message_length,
                                                  "x-pEp/message", NULL);
        if (added_bloblist == NULL) {
            status = PEP_OUT_OF_MEMORY;
            goto end;
        }
        set_blob_disposition(added_bloblist, PEP_CONTENT_DISP_ATTACHMENT);
        res->attachments = added_bloblist;
        encoded_message = NULL; /* do not free this twice */

        /* Replace res with an encrypted version of itself. */
#if defined(ONION_DEBUG_ENCRYPT)
        message *res_encrypted = NULL;
        status
            = encrypt_message_possibly_with_media_key(session, res, extra,
                                                      & res_encrypted,
                                                      enc_format, flags, NULL);
        LOG_NONOK_STATUS_NONOK;
        if (status != PEP_STATUS_OK)
            goto end;
        free_message(res);
        res = res_encrypted;
#endif
    }

end:
    /* Free the temporary data we need to dispose of in either case, success or
       error. */
    free(encoded_message);
    free(shortmsg);
    free(longmsg);
    free_identity(from_copy);
    free_identity_list(tos_copy);

    if (status == PEP_STATUS_OK)
        * out_p = res;
    else {
        free_message(res);
    }
    LOG_NONOK_STATUS_NONOK;
    return status;
}

DYNAMIC_API PEP_STATUS onionize(PEP_SESSION session,
                                message *in, message **out_p,
                                PEP_enc_format enc_format,
                                PEP_encrypt_flags_t flags,
                                identity_list *relays_as_list)
{
    PEP_REQUIRE(session && in && in->dir == PEP_dir_outgoing && out_p
                && enc_format == PEP_enc_PEP_message_v2
                && ! (flags & PEP_encrypt_onion)
                //&& identity_list_length(relays_as_list) >= 3
                );
    PEP_STATUS status = PEP_STATUS_OK;

    /* Initialise the output parameter, for defensiveness's sake.  We will only
       set the actual pointer to a non-NULL value at the end, on success. */
    * out_p = NULL;

    message *out = NULL;
    out = message_dup(in);
    size_t relay_no = identity_list_length(relays_as_list);
    pEp_identity **relay_array = NULL;
    pEp_identity *layer_from = NULL;
    pEp_identity *layer_to = NULL;
    pEp_identity *original_from = in->from;
    pEp_identity *original_to = in->to->ident;
    PEP_ASSERT(original_to != NULL);
    PEP_ASSERT(in->to->next == NULL);

    /* Make an array from the relay list; it will be much more convenient to
       scan in any order, looking at the previous and next element. */
    relay_array = calloc(relay_no, sizeof (pEp_identity *));
    if (relay_array == NULL) {
        status = PEP_OUT_OF_MEMORY;
        goto end;
    }
    int next_index = 0;
    identity_list *rest;
    for (rest = relays_as_list; rest != NULL; rest = rest->next) {
        if (rest->ident == NULL) continue; /* Ignore silly NULL identities. */
        pEp_identity *identity = rest->ident;
        if (identity->me) {
            status = PEP_ILLEGAL_VALUE;
            goto end;
        }
        relay_array [next_index] = identity;
        next_index ++;
    }

    /* Build the layers, inside-out. */
    size_t layer_no = (/* each relay receives one message */ relay_no
                       + /* last relay to recepient */ 1);
    int i;
    for (i = 0; i < layer_no; i ++) {
        /* Decide who From and To are. */
        bool innermost = (i == 0);
        //bool outermost = (i == layer_no - 1);
        layer_from = original_from;
        if (innermost)
            layer_to = original_to;
        else
            layer_to = relay_array [relay_no - i];
        //if (outermost)
        //    layer_from = original_from;
        //else
        //    layer_from = relay_array [relay_no - i - 1];
LOG_TRACE("Layer %i:  from %s  to  %s", i, layer_from->username, layer_to->username);
        /* Wrap the current "out" message into a new layer. */
        message *new_out = NULL;
        status = _onion_add_layer(session, out,
                                  /* FIXME: extra keys? */ NULL,
                                  & new_out,
                                  enc_format,
                                  flags | (innermost
                                           ? 0
                                           : PEP_encrypt_onion),
                                  layer_from, layer_to,
                                  innermost);
        if (status == PEP_STATUS_OK) {
            free_message(out);
            out = new_out;
        }
        else
            goto end;
    }

 end: __attribute__((unused));
    /* Free the temporary structures we need to release on both error and
       success. */
    free(relay_array);

    if (status == PEP_STATUS_OK)
        * out_p = out;
    else
        free_message(out);
    LOG_NONOK_STATUS_NONOK;
    return status;
}
