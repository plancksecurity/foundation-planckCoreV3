/**
  * @file	mixnet.h
  * @brief	module for mixnet functions in the pEp Engine
  * @license	GNU General Public License 3.0 - see LICENSE.txt
  */

#ifndef MIXNET_H
#define MIXNET_H

#include "pEpEngine.h"
#include "message_api.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
  * <!--	onionize_message()	-->
  *
  * @brief Onionionize Message; encrypt it several times
  *
  * @param[in]		session		session handle
  * @param[in]		src		message to onionize
  * qparam[in]		flags		flags to set special encryption features
  * @param[out]		dst		pointer to the onionized message
  *					or NULL if no encryption could take place
  * @retval PEP_STATUS_OK		on success
  * @retval PEP_ILLEGAL_VALUE		illegal parameter values
  * @retval PEP_OUT_OF_MEMORY		out of memory
  *
  * @warning		need more clarity about enc_format and flags
  */

DYNAMIC_API PEP_STATUS onionize_message
	(
	PEP_SESSION session,
	message *src,
	message **dst,
        PEP_encrypt_flags_t flags
	);

#ifdef __cplusplus
}
#endif
#endif
