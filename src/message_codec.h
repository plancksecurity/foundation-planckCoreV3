/**
 * @file        message_codec.h
 * @brief       Definitions for ASN1Message encode and decode functions which transform message payloads to
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


struct ASN1Message;

/**
 *  <!--         decode_ASN1Message_message()       -->
 *
 *  @brief       decode PER encoded ASN1Message message
 *
 *  @param[in]   data             PER encoded data
 *  @param[in]   size             size of PER encoded data
 *  @param[out]  msg              decoded ASN1Message message
 *
 *  @retval      status
 *
 *  @ownership   msg goes into the ownership of the caller
 */
DYNAMIC_API PEP_STATUS decode_ASN1Message_message(
        const char *data,
        size_t size,
        struct ASN1Message **msg
    );

/**
 *  <!--         encode_ASN1Message_message()       -->
 *
 *  @brief       decode PER encoded ASN1Message message
 *
 *  @param[in]   msg              ASN1Message message to encode
 *  @param[out]  data             PER encoded data
 *  @param[out]  size             size of PER encoded data
 *
 *  @retval      status
 *
 *  @ownership   msg goes into the ownership of the caller
 */
DYNAMIC_API PEP_STATUS encode_ASN1Message_message(
        struct ASN1Message *msg,
        char **data,
        size_t *size
    );


/**
 *  <!--         PER_to_XER_ASN1Message_msg()       -->
 *
 *  @brief          decode ASN1Message message from PER into XER
 *
 *  @param[in]   data       PER encoded data
 *  @param[in]   size       size of PER encoded data
 *  @param[out]  text       XER text of the same ASN1Message message
 *
 *  @retval      status
 */
DYNAMIC_API PEP_STATUS PER_to_XER_ASN1Message_msg(
        const char *data,
        size_t size,
        char **text
    );

/**
 *  <!--         XER_to_PER_ASN1Message_msg()       -->
 *
 *  @brief          encode ASN1Message message from XER into PER
 *
 *  @param[in]   text       string text with XER text of the ASN1Message message
 *  @param[out]  data       PER encoded data
 *  @param[out]  size       size of PER encoded data
 *
 *  @retval      status
 */
DYNAMIC_API PEP_STATUS XER_to_PER_ASN1Message_msg(
        const char *text,
        char **data,
        size_t *size
    );


/**
 *  <!--         free_ASN1Message()       -->
 *
 *  @brief          De-allocate the pointed ASN1 message which must have been
 *                  heap-allocated.
 *
 *  @param[in]      msg       Pointer to the message to destroy.
 */
DYNAMIC_API void free_ASN1Message(
        ASN1Message_t *msg
    );


#ifdef __cplusplus
}
#endif
#endif

