/**
 * @file        PEPMessage_codec.h
 * @brief       Definitions for PEPMessage encode and decode functions which transform message payloads to
 *              and from PER-encoded data, and XER text to and from PER
 *
 * @see         https://www.itu.int/en/ITU-T/asn1/Pages/introduction.aspx
 *
 * @license     GNU General Public License 3.0 - see LICENSE.txt
 */


#ifndef PEPMESSAGE_CODEC_H
#define PEPMESSAGE_CODEC_H

#include "pEpEngine.h"


#ifdef __cplusplus
extern "C" {
#endif


struct PEPMessage;

/**
 *  <!--         decode_PEPMessage_message()       -->
 *
 *  @brief       decode PER encoded PEPMessage message
 *
 *  @param[in]   data             PER encoded data
 *  @param[in]   size             size of PER encoded data
 *  @param[out]  msg              decoded PEPMessage message
 *
 *  @retval      status
 *
 *  @ownership   msg goes into the ownership of the caller
 */
DYNAMIC_API PEP_STATUS decode_PEPMessage_message(
        const char *data,
        size_t size,
        struct PEPMessage **msg
    );

/**
 *  <!--         encode_PEPMessage_message()       -->
 *
 *  @brief       decode PER encoded PEPMessage message
 *
 *  @param[in]   msg              PEPMessage message to encode
 *  @param[out]  data             PER encoded data
 *  @param[out]  size             size of PER encoded data
 *
 *  @retval      status
 *
 *  @ownership   msg goes into the ownership of the caller
 */
DYNAMIC_API PEP_STATUS encode_PEPMessage_message(
        struct PEPMessage *msg,
        char **data,
        size_t *size
    );


/**
 *  <!--         PER_to_XER_PEPMessage_msg()       -->
 *
 *  @brief          decode PEPMessage message from PER into XER
 *
 *  @param[in]   data       PER encoded data
 *  @param[in]   size       size of PER encoded data
 *  @param[out]  text       XER text of the same PEPMessage message
 *
 *  @retval      status
 */
DYNAMIC_API PEP_STATUS PER_to_XER_PEPMessage_msg(
        const char *data,
        size_t size,
        char **text
    );

/**
 *  <!--         XER_to_PER_PEPMessage_msg()       -->
 *
 *  @brief          encode PEPMessage message from XER into PER
 *
 *  @param[in]   text       string text with XER text of the PEPMessage message
 *  @param[out]  data       PER encoded data
 *  @param[out]  size       size of PER encoded data
 *
 *  @retval      status
 */
DYNAMIC_API PEP_STATUS XER_to_PER_PEPMessage_msg(
        const char *text,
        char **data,
        size_t *size
    );


#ifdef __cplusplus
}
#endif
#endif

