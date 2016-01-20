#pragma once

#include "pEpEngine.h"

#ifdef __cplusplus
extern "C" {
#endif

// update_identity() - update identity information
//
//  parameters:
//      session (in)        session to use
//      identity (inout)    identity information of communication partner
//
//  caveat:
//      if this function returns PEP_ct_unknown or PEP_ct_key_expired in
//      identity->comm_type, the caller must insert the identity into the
//      asynchronous management implementation, so retrieve_next_identity()
//      will return this identity later
//      at least identity->address must be a non-empty UTF-8 string as input

DYNAMIC_API PEP_STATUS update_identity(
        PEP_SESSION session, pEp_identity * identity
    );


// myself() - ensures that the own identity is being complete
//
//  parameters:
//      session (in)        session to use
//      identity (inout)    identity of local user
//                          at least .address, .username, .user_id must be set
//
//  return value:
//      PEP_STATUS_OK if identity could be completed or was already complete,
//      any other value on error
//
//  caveat:
//      this function generates a keypair on demand; because it's synchronous
//      it can need a decent amount of time to return
//      if you need to do this asynchronous, you need to return an identity
//      with retrieve_next_identity() where pEp_identity.me is true

DYNAMIC_API PEP_STATUS myself(PEP_SESSION session, pEp_identity * identity);


// retrieve_next_identity() - callback being called by do_keymanagement()
//
//  parameters:
//      management (in)     data structure to deliver (implementation defined)
//
//  return value:
//      identity to check or NULL to terminate do_keymanagement()
//      if given identity must be created with new_identity()
//      the identity struct is going to the ownership of this library
//      it must not be freed by the callee
//
//  caveat:
//      this callback has to block until an identity or NULL can be returned
//      an implementation is not provided by this library; instead it has to be
//      implemented by the user of this library

typedef pEp_identity *(*retrieve_next_identity_t)(void *management);


// examine_identity() - callback for appending to queue
//
//  parameters:
//      ident (in)          identity to examine
//      management (in)     data structure to deliver (implementation defined)
//
//  return value:
//      0 if identity was added successfully to queue or nonzero otherwise

typedef int (*examine_identity_t)(pEp_identity *ident, void *management);


// register_examine_function() - register examine_identity() callback
//
//  parameters:
//      session (in)            session to use
//      examine_identity (in)   examine_identity() function to register
//      management (in)     data structure to deliver (implementation defined)

DYNAMIC_API PEP_STATUS register_examine_function(
        PEP_SESSION session, 
        examine_identity_t examine_identity,
        void *management
    );


// do_keymanagement() - function to be run on an extra thread
//
//  parameters:
//      retrieve_next_identity  pointer to retrieve_next_identity() callback
//                              which returns at least a valid address field in
//                              the identity struct
//      management              management data to give to keymanagement
//                              (implementation defined)
//
//  return value:
//      PEP_STATUS_OK if thread has to terminate successfully or any other
//      value on failure
//
//  caveat:
//      to ensure proper working of this library, a thread has to be started
//      with this function immediately after initialization
//      do_keymanagement() calls retrieve_next_identity(management)

DYNAMIC_API PEP_STATUS do_keymanagement(
        retrieve_next_identity_t retrieve_next_identity,
        void *management
    );


// key_compromized() - mark key as being compromized
//
//  parameters:
//      session (in)        session to use
//      ident (in)          person and key which was compromized

DYNAMIC_API PEP_STATUS key_compromized(
        PEP_SESSION session,
        pEp_identity *ident
    );


// trust_personal_key() - mark a key as trusted with a person
//
//  parameters:
//      session (in)        session to use
//      ident (in)          person and key to trust in
//
//  caveat:
//      the fields user_id, address and fpr must be supplied

DYNAMIC_API PEP_STATUS trust_personal_key(
        PEP_SESSION session,
        pEp_identity *ident
    );


// key_reset_trust() - undo trust_personal_key and key_compromized() for keys
//                     we don't own
//
//  parameters:
//      session (in)        session to use
//      ident (in)          person and key which was compromized

DYNAMIC_API PEP_STATUS key_reset_trust(
        PEP_SESSION session,
        pEp_identity *ident
    );


#ifdef __cplusplus
}
#endif

