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

// key_reset_identity() - resets trust status for this identity and fpr, and remove
//                        this fpr as a default for all identities and users and from 
//                        the keyring.
//                        
//                        If the fpr is NULL, we will reset the identity default fpr
//                        as above. When that does not exist, then we do it for 
//                        the user default. 
//
//                        For own identities, when the fpr has a private key part,
//                        also revoke the key and communicate the revocation and new key 
//                        to partners we have sent mail to recently from the specific identity 
//                        (i.e. address/user_id) that contacted them. We also in this case 
//                        set up information so that if someone we mail uses the wrong key 
//                        and wasn't yet contacted, we can send them the reset information 
//                        from the right address. 
//
//  parameters:
//      session (in)            session handle
//      fpr (in)                fingerprint of key to reset. If NULL, we reset the default key
//                              this user, if there is one.
//      ident (in)              identity for which the key reset should occur. Must contain 
//                              user_id and address.
//
//                              fpr field will be ignored. Cannot be NULL.
//
//      Note: ident->fpr is always ignored
//
//
DYNAMIC_API PEP_STATUS key_reset_identity(
        PEP_SESSION session,
        const char* fpr,
        pEp_identity* ident
    );

// key_reset_user() - reset the default key database status for each identity 
//                    corresponding to this user and fpr (if present), and remove from 
//                    the keyring. This will also remove the key(s) from all other 
//                    users and identities. If no fpr is present, reset all default keys 
//                    corresponding to this user and its identities.
//           
//                    For own keys, also revoke the key(s) and communicate the 
//                    revocation and new key(s) to partners we have sent mail to 
//                    recently from the specific identities (i.e. address/user_id) 
//                    that contacted them. We also in this case set up information 
//                    so that if someone we mail uses the wrong key and wasn't 
//                    yet contacted, we can send them the reset information 
//                    from the right address.
//
//                    If the user_id is NULL and fpr is NULL, we reset all keys for the own user. 
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
//                              the default key for this identity.
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
