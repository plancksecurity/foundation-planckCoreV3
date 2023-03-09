/**
  * @file	mixnet.c
  * @brief	implementation of mixnet functions for the pEp Engine
  * @license	GNU General Public License 3.0 - see LICENSE.txt
  */

#include "pEp_internal.h"
#include "mixnet.h"
#include "identity_list.h"


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

	//check if everything is OK
	PEP_STATUS status = PEP_STATUS_OK;

	if(!(session && src && src->from && dst))
		return PEP_ILLEGAL_VALUE;

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
	rev=identity_list_revert(src->cc);

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
	return status;

enomem:
	status = PEP_OUT_OF_MEMORY;

pEp_error:
	return status;

	}

