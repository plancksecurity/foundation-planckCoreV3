/**
  * @file	mixnet.c
  * @brief	implementation of mixnet functions for the pEp Engine
  * @license	GNU General Public License 3.0 - see LICENSE.txt
  */

#include "pEp_internal.h"
#include "mixnet.h"
#include "identity_list.h"


/* Copy the elements of the given in-list into the out-list; in the copy, for
   each element, call myself if the element is own, and update_identity
   otherwise.  Do not modify the in-list.  Return PEP_STATUS_OK on success;
   other values in case of error.
   In case of an out-of-memory error this function returns PEP_OUT_OF_MEMORY
   *and* also sets *out to be NULL. */
static PEP_STATUS reverse_and_update(PEP_SESSION session,
                                     identity_list **out,
                                     identity_list *in) {
    PEP_REQUIRE(session && out && in);
    PEP_STATUS status = PEP_STATUS_OK;

    /* Make out be empty at the beginning: we will add elements to it. */
    *out = NULL;

    identity_list *rest_of_in;
    for (rest_of_in = in; rest_of_in != NULL; rest_of_in = rest_of_in->next) {
        /* in_ident is the current element. */
        pEp_identity *in_ident = rest_of_in->ident;
        PEP_ASSERT(in_ident != NULL);

        /* We want to copy and update ident, for adding it to our new list. */
        pEp_identity *out_ident = identity_dup(in_ident);
        if (out_ident == NULL)
            goto out_of_memory;
        if (in_ident->me)
            status = myself(session, out_ident);
        else
            status = update_identity(session, out_ident);
        if (status != PEP_STATUS_OK)
            goto error;

        /* ident is the next element of in; we want to prepend an updated copy
           of it to the beginning of out; at the end out will be reversed
           compared to in. */
        identity_list *new_element = malloc(sizeof (identity_list));
        if (new_element == NULL)
            goto out_of_memory;
        new_element->ident = out_ident;
        new_element->next = * out;
        * out = new_element;
    }
    return status;

 error:
    /* Free the out list, which we did not manage to complte. */
    identity_list *rest_of_out = * out;
    while (rest_of_out != NULL) {
        /* Read a copy of the next pointer from the struct I am about to
           destroy; it would be wrong to read it after destroying it. */
        identity_list *rest_of_rest_of_out = rest_of_out->next;

        /* Destroy first the identity, pointed by the struct, then the struct
           itself. */
        free_identity(rest_of_out->ident);
        free(rest_of_out);

        /* We are done with this element.  Go on with the rest. */
        rest_of_out = rest_of_rest_of_out;
    }
    /* Just for defensiveness's sake, let us make the out list empty. */
    * out = NULL;
    PEP_ASSERT(status == PEP_STATUS_OK);
    return status;

 out_of_memory:
    status = PEP_OUT_OF_MEMORY;
    goto error;
}

/* This is the onionize function.
   For now, it is only for testing purposes.
   The shortmsg is abused as a flag to signalise the message is an onion message
   The list of CCs are abused to transmit the identities of the onion nodes
   The "|||" in the LOG_TRACE commands help to filter log messages using grep.
*/

DYNAMIC_API PEP_STATUS onionize_message(
	PEP_SESSION session,
	message *src,
        stringlist_t * extra,
	message **dst,
	PEP_enc_format enc_format,
        PEP_encrypt_flags_t flags
	)
{
        PEP_REQUIRE(session && src && src->from && dst);

	PEP_STATUS status = PEP_STATUS_OK;


	*dst=NULL;

	LOG_TRACE("||| Onionizing message");


	//set the flag for onion message
        PEP_encrypt_flags_t onion_flags = flags | PEP_encrypt_onion;

	//encrypt the message for the final recipient.
	status = encrypt_message_possibly_with_media_key
                 (
                 session,
                 src,
		 extra,
                 dst,
                 enc_format,
                 onion_flags,
                 NULL);

	LOG_TRACE("||| Status: %d", (int) status);


	//check if there are at least 3 CCs
	if(identity_list_length(src->cc) < 3)
		{
		LOG_TRACE("||| To few onion nodes");
		return PEP_ILLEGAL_VALUE;
		}

	//revert the list of CCs
	identity_list * rev;
        status = reverse_and_update(session, & rev, src->cc);

	//loop through the reverted linked list
	identity_list * temp;
	pEp_identity * temp_ident;
	int i=0;
	while (rev)
 		{
			LOG_TRACE("||| looping... %d",i);
        		i++;
			temp = rev;
			if (rev->next)
				{
				rev=rev->next;
				}
			else
				{
				rev=NULL;
				}
			temp_ident=temp->ident;
			LOG_TRACE("||| encrypting for identity: %s", temp_ident->username);
			//TODO: call the encrypt function the right way
		}
	LOG_TRACE("||| Encryption loop finished");
        free_identity_list(rev);
	return status;

enomem: __attribute__ ((unused))
	status = PEP_OUT_OF_MEMORY;

pEp_error: __attribute__ ((unused))
        free_identity_list(rev);
	return status;

	}

