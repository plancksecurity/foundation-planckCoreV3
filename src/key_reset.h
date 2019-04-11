// This file is under GNU General Public License 3.0
// see LICENSE.txt

#pragma once

#include "key_reset.h"

#include "pEpEngine.h"
#include "keymanagement.h"
#include "message.h"
#include "message_api.h"
#include "cryptotech.h"

#ifdef __cplusplus
extern "C" {
#endif

// key_reset_identity() - reset the default database status for the identity / keypair
//                        provided. If this corresponds to the own user and a private key,
//                        also revoke the key, generate a new one, and communicate the 
//                        reset to recently contacted pEp partners for this identity.
//                        If it does not, remove the key from the keyring; the key's 
//                        status is completely fresh on next contact from the partner.
//
//                        If ident contains both a user_id and an address, and this is 
//                        not the own_user:
//                        1. If the fpr is non-NULL, we will delete this key from the keyring, 
//                           remove this fpr as the default for all users and all identities,
//                           and remove all key information for this key in the DB
//                        2. If the fpr IS NULL, we will do what is in step 1 for the default 
//                           key for this identity, and if there is not one, we do it for the 
//                           user default key.                             
//                        
//                        If ident contains both a user_id and an address, and 
//                        this IS the own_user:
//                        1. If the fpr is non-NULL and the corresponding key has a private part,
//                           we will revoke and mistrust this key, generate a new key for this identity,
//                           and communicate the revocation and new key to partners we have 
//                           sent mail to recently from the specific identity (i.e. address/user_id) 
//                           that contacted them. We also in this case set up information so 
//                           that if someone we mail uses the wrong key and wasn't yet contacted, 
//                           we can send them the reset information from the right address.
//                        2. If the fpr is non-NULL and does NOT correspond to a private key,
//                           this behaves the same way as with a non-own user above.
//                        3. If the fpr is NULL, we perform the steps in 1. of this section for 
//                           the identity default if it exists, and if not, the user default. 
//
//                        If the ident only contains a user_id, we perform the above for every key 
//                        associated with the user id. In the case of own private keys, we then 
//                        go through each identity associated with the key and reset those identities 
//                        as indicated above. (keys not associated with any identity will not
//                        have replacement information or keys generated)
//
//                        If the identity is NULL, this is the same as calling the function with an
//                        identity containing only the own user_id (and no address).
//
//  parameters:
//      session (in)            session handle
//      fpr (in)                fingerprint of key to reset. If NULL, we reset the default key
//                              this identity if there is one, and the user default if not.
//      ident (in)              identity for which the key reset should occur. Must contain 
//                              user_id, at a minimum. If it contains no address, all keys for this user
//                              are reset. If NULL, all keys for the own user will be reset.
//
//                              Note: ident->fpr field will be ignored.
//
//
DYNAMIC_API PEP_STATUS key_reset_identity(
        PEP_SESSION session,
        const char* fpr,
        pEp_identity* ident
    );

// key_reset_user() -  reset the default database status for the user / keypair
//                     provided. This will effectively perform key_reset_identity()
//                     each identity associated with the key and user_id, if a key is
//                     provided, and for each key (and all of their identities) if an fpr 
//                     is not.
//
//                     See key_reset_identity() under identities containing only user_id.
//
//
//  parameters:
//      session (in)            session handle
//      fpr (in)                fingerprint of key to reset. If NULL and user_id is NULL,
//                              we reset all keys for the own user. If NULL, we reset all default 
//                              keys for this user and all of its identities.
//      user_id (in)            user_id for which the key reset should occur.
//                              If the user_id is NULL, we reset keys for the own user.
//
DYNAMIC_API PEP_STATUS key_reset_user(
        PEP_SESSION session,
        const char* fpr,
        const char* user_id
    );

// key_reset() - reset the database status for a key, removing all trust information
//               and default database connections. For own keys, also revoke the key
//               and communicate the revocation and new key to partners we have sent
//               mail to recently from the specific identity (i.e. address/user_id)
//               that contacted them. We also in this case set up information so that
//               if someone we mail uses the wrong key and wasn't yet contacted,
//               we can send them the reset information from the right address. 
//               For non-own keys, also remove key from the keyring.
//
//               Can be called manually or through another protocol.
//
//  parameters:
//      session (in)            session handle
//      fpr (in)                fingerprint of key to reset. If NULL and ident is NULL,
//                              we reset all keys for the own user. If NULL and ident is
//                              an own identity, we reset the default key for that
//                              identity. If that own identity has no default key, we
//                              reset the user default.
//                              if it is NULL and there is a non-own identity, we will reset 
//                              the default key for this identity if present, and user if not.
//      ident (in)              identity for which the key reset should occur.
//                              if NULL and fpr is non-NULL, we'll reset the key for all
//                              associated identities. If both ident and fpr are NULL, see 
//                              the fpr arg documentation.
//
//      Note: ident->fpr is always ignored
//
// Caveat: this is now used in large part for internal calls.
//         external apps should call key_reset_identity and key_reset_userdata
//         and this function should probably be removed from the dynamic api
PEP_STATUS key_reset(
        PEP_SESSION session,
        const char* fpr,
        pEp_identity* ident
    );



PEP_STATUS has_key_reset_been_sent(
        PEP_SESSION session, 
        const char* user_id, 
        const char* revoked_fpr,
        bool* contacted);

PEP_STATUS set_reset_contact_notified(
        PEP_SESSION session,
        const char* revoke_fpr,
        const char* contact_id
    );

PEP_STATUS receive_key_reset(PEP_SESSION session,
                             message* reset_msg);

PEP_STATUS create_standalone_key_reset_message(PEP_SESSION session,
                                               message** dst, 
                                               pEp_identity* recip,
                                               const char* old_fpr,
                                               const char* new_fpr);
                                               
PEP_STATUS send_key_reset_to_recents(PEP_SESSION session,
                                     const char* old_fpr, 
                                     const char* new_fpr);
    
#ifdef __cplusplus
}
#endif
