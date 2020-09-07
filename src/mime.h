/**
 * @file    mime.h
 * @brief   mime functionality as produced/consumed by the engine. This is the interface to the engine's
 *          use of the underlying MIME parser
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#pragma once

#include "message.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  <!--       is_PGP_message_text()       -->
 *  
 *  @brief Determine if text encodes a PGP message
 *  
 *  @param[in]     text    text to examine
 *  
 *  @retval true if text is a PGP message, false otherwise
 *  
 *  
 */

DYNAMIC_API bool is_PGP_message_text(const char *text);


/**
 *  <!--       mime_encode_message()       -->
 *  
 *  @brief Encode a MIME message
 *  
 *  @param[in]     msg                       message to encode
 *  @param[in]     omit_fields               only encode message body and 
 *                                           attachments
 *  @param[out]    mimetext                  the resulting encoded text or 
 *                                           NULL on any error
 *  @param[in]     has_pEp_msg_attachment    is the first *attachment* to this 
 *                                           message an embedded pEp message
 *                                           which needs appropriate marking
 *                                           (forwarded=no, etc) and encoding?
 *                                           (this argument is internal to 
 *                                           pEp and should almost
 *                                           ALWAYS be false when used 
 *                                           by external callers, including
 *                                           adapters!!!)
 *  
 *  @retval PEP_STATUS_OK           if everything worked
 *  @retval PEP_BUFFER_TOO_SMALL    if encoded message size is too big to handle
 *  @retval PEP_CANNOT_CREATE_TEMP_FILE
 *  @retval if there are issues with temp files; in
 *  @retval this case errno will contain the underlying
 *  @retval error
 *  @retval PEP_OUT_OF_MEMORY       if not enough memory could be allocated
 *  
 *  @warning the resulttext will go to the ownership of the caller
 *           the message will remain in the ownership of the caller
 *           omit_fields is true for payload of PGP/MIME messages
 *           also: note that the encryption type will be used to determine what
 *           gets encoded from the message struct, so if using this on an 
 *           already-encrypted message, set the enc_format of the msg to PEP_enc_none.
 *  
 */

DYNAMIC_API PEP_STATUS mime_encode_message(
        const message * msg,
        bool omit_fields,
        char **mimetext,
        bool has_pEp_msg_attachment     
    );


/**
 *  <!--       mime_decode_message()       -->
 *  
 *  @brief Decode a MIME message
 *  
 *  @param[in]     mimetext                MIME encoded text to decode
 *  @param[in]     size                    size of text to decode
 *  @param[out]    msg                     decoded message
 *  @param[in,out] has_possible_pEp_msg    If non-NULL, will return 
 *                                         true when the first attachment 
 *                                         is a potential pEp message
 *                                         (mime-type = message/rfc822 and 
 *                                         content-disposition parameter
 *                                         forwarded=no) 
 *  
 *  @retval PEP_STATUS_OK           if everything worked
 *  @retval PEP_BUFFER_TOO_SMALL    if encoded message size is too big to handle
 *  @retval PEP_CANNOT_CREATE_TEMP_FILE
 *  @retval if there are issues with temp files; in
 *  @retval this case errno will contain the underlying
 *  @retval error
 *  @retval PEP_OUT_OF_MEMORY       if not enough memory could be allocated
 *  
 *  @warning the decoded message will go to the ownership of the caller; mimetext
 *           will remain in the ownership of the caller
 *  
 */

DYNAMIC_API PEP_STATUS mime_decode_message(
        const char *mimetext,
        size_t size,
        message **msg,
        bool* has_possible_pEp_msg
    );

#ifdef __cplusplus
}
#endif
