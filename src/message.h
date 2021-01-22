// This file is under GNU General Public License 3.0
// see LICENSE.txt

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


typedef enum _PEP_text_format {
    PEP_text_format_plain = 0,
    PEP_text_format_html,
    PEP_text_format_other = 0xff
} PEP_text_format;

typedef enum _PEP_msg_direction {
    PEP_dir_incoming = 0,
    PEP_dir_outgoing
} PEP_msg_direction;

struct _message_ref_list;

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
    stringlist_t *references;               // list of UTF-8 strings with references
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

typedef struct _message_ref_list {
    message *msg_ref;                       // reference to message
    struct _message_ref_list *next;
} message_ref_list;

// new_message() - allocate new message
//
//  parameters:
//      dir (in)        PEP_dir_incoming or PEP_dir_outgoing
//
//  return value:
//      pointer to new message or NULL if out of memory

DYNAMIC_API message *new_message(
        PEP_msg_direction dir
    );


// free_message() - free message struct
//
//  parameters:
//      msg (in)        message struct to free
//
//  NOTA BENE:
//      raw data (msg->rawmsg_ref) and referenced other messages (msg->refering_msg_ref)
//      aren't freed and remain in the ownership of the caller!

DYNAMIC_API void free_message(message *msg);


// message_dup - duplicate message (deep copy)
//
//  parameters:
//      msg (in)        message to duplicate
//
//  return value:
//      pointer to duplicate of message pointed by msg or NULL
//  NOTA BENE:
//      not owned pointees (msg->rawmsg_ref and msg->refering_msg_ref) are shared!

DYNAMIC_API message * message_dup(const message *msg);

// message_transfer - assign ownership of all fields of the src message to
//                    the dst message object passed in. Free respective memory
//                    in the dst message, and reinitialise and pointers in 
//                    the src message to NULL so that it can be freed properly
//                    by its owner.
//  parameters:
//      dst (inout)        message to clobber and reassign values to
//      src (inout)        message whose values will be transfered to dst
//  NOTA BENE:
//      not owned pointees (msg->rawmsg_ref and msg->refering_msg_ref) are shared!
//      these are simply transferred.
DYNAMIC_API void message_transfer(message* dst, message *src);


// new_message_ref_list() - allocate new message reference list
//
//  parameters:
//      msg (in)        message to add a reference to or NULL
//
//  return value:
//      pointer to new message_ref_list or NULL if out of memory

DYNAMIC_API message_ref_list *new_message_ref_list(message *msg);


// free_message_ref_list() - free message reference list
//
//  parameters:
//      msg_list (in)   message_ref_list to free

DYNAMIC_API void free_message_ref_list(message_ref_list *msg_list);


// message_ref_list_dup() - duplicate message reference list
//
//  paramters:
//      src (in)        message_ref_list to duplicate
//
//  return value:
//      pointer to new message_ref_list or NULL if out of memory

DYNAMIC_API message_ref_list *message_ref_list_dup(
        const message_ref_list *src
    );

// message_ref_list_add() - add a reference to a message to a message reference
// list
//
//  parameters:
//      msg_list (in)   message_ref_list to add to
//      msg (in)        message to add a reference to
//
//  return value:
//      pointer to the last element of message_ref_list or NULL if out of
//      memory

DYNAMIC_API message_ref_list *message_ref_list_add(message_ref_list *msg_list,
        message *msg);


#ifdef __cplusplus
}
#endif

#endif
