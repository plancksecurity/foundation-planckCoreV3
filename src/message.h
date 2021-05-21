/**
 * @file    message.h
 * @brief   the pEp message structure and functions used to represent messages and pass message 
 *          information back and forth between the engine and its customers. Includes memory management
 *          for said structs.
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#ifndef MESSAGE_H
#define MESSAGE_H

#include <time.h>

#include "pEpEngine.h"
#include "identity_list.h"
#include "bloblist.h"
#include "stringlist.h"
#include "stringpair.h"
#include "timestamp.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 *  @enum PEP_text_format
 *  
 *  @brief TODO
 *  
 */
typedef enum _PEP_text_format {
    PEP_text_format_plain = 0,
    PEP_text_format_html,
    PEP_text_format_other = 0xff
} PEP_text_format;

/**
 *  @enum PEP_msg_direction
 *  
 *  @brief TODO
 *  
 */
typedef enum _PEP_msg_direction {
    PEP_dir_incoming = 0,
    PEP_dir_outgoing
} PEP_msg_direction;

struct _message_ref_list;

/**
 *  @struct message
 *  
 *  @brief TODO
 *  
 */
typedef struct _message {
    PEP_msg_direction dir;
    char *id;                               // UTF-8 string of message ID
    char *shortmsg;                         // UTF-8 string of short message
    char *longmsg;                          // UTF-8 string of long message
                                            // (plain)
    char *longmsg_formatted;                // UTF-8 string of long message
                                            // (formatted)
    bloblist_t *attachments;                // blobs with attachements
    char *rawmsg_ref;                       // reference to raw message data
    size_t rawmsg_size;                     // size of raw message data
    timestamp *sent;                        // when the message is sent
    timestamp *recv;                        // when the message is received
    pEp_identity *from;                     // whom the message is from
    identity_list *to;                      // whom the message is to
    pEp_identity *recv_by;                  // via which identity the message
                                            // is received
    identity_list *cc;                      // whom a CC is being sent
    identity_list *bcc;                     // whom a BCC is being sent
    identity_list *reply_to;                // where a reply should go to
    stringlist_t *in_reply_to;              // list of UTF-8 strings with
                                            // MessageIDs of refering messages
    struct _message *refering_msg_ref;      // reference to refering message
    stringlist_t * references;               // list of UTF-8 strings with references
    struct _message_ref_list *refered_by;   // list of references to messages being
                                            // refered
    stringlist_t *keywords;                 // list of UTF-8 strings with keywords
    char *comments;                         // UTF-8 string with comments
    stringpair_list_t *opt_fields;          // optional fields
    PEP_enc_format enc_format;              // format of encrypted data
    char* _sender_fpr;                      // INTERNAL USE ONLY - fingerprint of 
                                            // sending signer.
                                            // (read_only to the outside)
} message;

/**
 *  @struct message_ref_list
 *  
 *  @brief TODO
 *  
 */
typedef struct _message_ref_list {
    message *msg_ref;                       // reference to message
    struct _message_ref_list *next;
} message_ref_list;

/**
 *  <!--       new_message()       -->
 *  
 *  @brief Allocate new message
 *  
 *  @param[in]   dir    PEP_dir_incoming or PEP_dir_outgoing
 *  
 *  @retval pointer to new message or NULL if out of memory
 *  
 *  
 */

DYNAMIC_API message *new_message(
        PEP_msg_direction dir
    );


/**
 *  <!--       free_message()       -->
 *  
 *  @brief Free message struct
 *  
 *  @param[in]   msg    message struct to free
 *                        NOTA BENE:
 *                        raw data (msg->rawmsg_ref) and referenced other messages (msg->refering_msg_ref)
 *                        aren't freed and remain in the ownership of the caller!
 *  
 *  
 */

DYNAMIC_API void free_message(message *msg);


/**
 *  <!--       message_dup()       -->
 *  
 *  @brief Duplicate message (deep copy)
 *  
 *  @param[in]   msg    message to duplicate
 *  
 *  @retval pointer to duplicate of message pointed by msg or NULL
 *          NOTA BENE:
 *          not owned pointees (msg->rawmsg_ref and msg->refering_msg_ref) are shared!
 *  
 *  
 */

DYNAMIC_API message * message_dup(const message *msg);

/**
 *  <!--       message_transfer()       -->
 *  
 *  @brief Assign ownership of all fields of the src message to
 *         the dst message object passed in. Free respective memory
 *         in the dst message, and reinitialise and pointers in 
 *         the src message to NULL so that it can be freed properly
 *         by its owner.
 *  
 *  @param[in,out] dst    message to clobber and reassign values to
 *  @param[in,out] src    message whose values will be transfered to dst
 *                        NOTA BENE:
 *                        not owned pointees (msg->rawmsg_ref and msg->refering_msg_ref) are shared!
 *                        these are simply transferred.
 *  
 *  
 */
DYNAMIC_API void message_transfer(message* dst, message *src);


/**
 *  <!--       new_message_ref_list()       -->
 *  
 *  @brief Allocate new message reference list
 *  
 *  @param[in]   msg    message to add a reference to or NULL
 *  
 *  @retval pointer to new message_ref_list or NULL if out of memory
 *  
 *  
 */

DYNAMIC_API message_ref_list *new_message_ref_list(message *msg);


/**
 *  <!--       free_message_ref_list()       -->
 *  
 *  @brief Free message reference list
 *  
 *  @param[in]   msg_list    message_ref_list to free
 *  
 *  
 */

DYNAMIC_API void free_message_ref_list(message_ref_list *msg_list);


/**
 *  <!--       message_ref_list_dup()       -->
 *  
 *  @brief Duplicate message reference list
 *  
 *  paramters:
 *  src (in)        message_ref_list to duplicate
 *  
 *  @retval pointer to new message_ref_list or NULL if out of memory
 *  
 *  
 */

DYNAMIC_API message_ref_list *message_ref_list_dup(
        const message_ref_list *src
    );

/**
 *  <!--       message_ref_list_add()       -->
 *  
 *  @brief Add a reference to a message to a message reference
 *         list
 *  
 *  @param[in]   msg_list    message_ref_list to add to
 *  @param[in]   msg         message to add a reference to
 *  
 *  @retval pointer to the last element of message_ref_list or NULL if out of
 *          memory
 *  
 *  
 */

DYNAMIC_API message_ref_list *message_ref_list_add(message_ref_list *msg_list,
        message *msg);


#ifdef __cplusplus
}
#endif

#endif
