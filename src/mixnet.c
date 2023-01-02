/**
  * @file	mixnet.c
  * @brief	implementation of mixnet functionality for the pEp Engine
  * @license	GNU General Public License 3.0 - see LICENSE.txt
  */

#include "pEp_internal.h"
#include "mixnet.h"
#include "identity_list.h"

DYNAMIC_API PEP_STATUS onionize_message(
	PEP_SESSION session,
	message *src,
	message **dst
	)
	{
	PEP_STATUS status = PEP_STATUS_OK;

	if(!(session && src && src->from && dst))
		return PEP_ILLEGAL_VALUE;

	*dst=NULL;
	LOG_TRACE("||| I am in the onionize_message function");
	LOG_TRACE("||| Number of CCs: %d",identity_list_length(src->cc));
        int tmp=src->cc;
	for(int i=0;tmp->next!=NULL;tmp=tmp->next)
		{
		LOG_TRACE("||| Looping");
		}

enomem:
	status = PEP_OUT_OF_MEMORY;

pEp_error:
	return status;

	}

