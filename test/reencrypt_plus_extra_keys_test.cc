// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string.h>
#include "platform.h"
#include <iostream>
#include <fstream>
#include <assert.h>
#include "mime.h"
#include "message_api.h"
#include "keymanagement.h"
#include "test_util.h"

using namespace std;

int main() {
    cout << "\n*** reencrypt_plus_extra_keys_test ***\n\n";

    PEP_SESSION session;
    
    cout << "calling init()\n";
    PEP_STATUS status = init(&session);
    assert(status == PEP_STATUS_OK);
    assert(session);
    cout << "init() completed.\n";

    /* import all the keys */
    const char* fpr_own_recip_key = "85D022E0CC9BA9F6B922CA7B638E5211B1A2BE89";
    const char* fpr_own_recip_2_key = "7A2EEB933E6FD99207B83E397B6D3751D6E75FFF";
    
    const char* fpr_sender_pub_key = "95FE24B262A34FA5C6A8D0AAF90144FC3B508C8E";
    const char* fpr_recip_2_pub_key = "60701073D138EF622C8F9221B6FC86831EDBE691";
    const char* fpr_recip_0_pub_key = "CDF787C7C9664E02825DD416C6FBCF8D1F4A5986";
    // we're leaving recip_1 out for the Hell of it - D3886D0DF75113BE2799C9374D6B99FE0F8273D8
    const char* fpr_pub_extra_key_0 = "33BB6C92EBFB6F29641C75B5B79D916C828AA789";
    const char* fpr_pub_extra_key_1 = "3DB93A746785FDD6110798AB3B193A9E8B026AEC";

    const string own_recip_pub_key = slurp("test_keys/pub/reencrypt_recip_0-0xB1A2BE89_pub.asc");
    const string own_recip_priv_key = slurp("test_keys/priv/reencrypt_recip_0-0xB1A2BE89_priv.asc");
    const string own_recip_2_pub_key = slurp("test_keys/pub/reencrypt_recip_numero_deux_test_0-0xD6E75FFF_pub.asc");
    const string own_recip_2_priv_key = slurp("test_keys/priv/reencrypt_recip_numero_deux_test_0-0xD6E75FFF_priv.asc");
    
    const string sender_pub_key = slurp("test_keys/pub/reencrypt_sender_0-0x3B508C8E_pub.asc");
    const string recip_2_pub_key = slurp("test_keys/pub/reencrypt_other_recip_2-0x1EDBE691_pub.asc");
    const string recip_0_pub_key = slurp("test_keys/pub/reencrypt_other_recip_0-0x1F4A5986_pub.asc");
    // we're leaving recip_1 out for the Hell of it
    const string pub_extra_key_0 = slurp("test_keys/pub/reencrypt_extra_keys_0-0x828AA789_pub.asc");
    const string pub_extra_key_1 = slurp("test_keys/pub/reencrypt_extra_keys_1-0x8B026AEC_pub.asc");

    status = import_key(session, own_recip_pub_key.c_str(), own_recip_pub_key.length(), NULL);
    assert (status == PEP_STATUS_OK);
    status = import_key(session, own_recip_priv_key.c_str(), own_recip_priv_key.length(), NULL);
    assert (status == PEP_STATUS_OK);    
    status = import_key(session, own_recip_2_pub_key.c_str(), own_recip_2_pub_key.length(), NULL);
    assert (status == PEP_STATUS_OK);
    status = import_key(session, own_recip_2_priv_key.c_str(), own_recip_2_priv_key.length(), NULL);
    assert (status == PEP_STATUS_OK);
    
    status = import_key(session, sender_pub_key.c_str(), sender_pub_key.length(), NULL);
    assert (status == PEP_STATUS_OK);
    status = import_key(session, recip_2_pub_key.c_str(), recip_2_pub_key.length(), NULL);
    assert (status == PEP_STATUS_OK);
    status = import_key(session, recip_0_pub_key.c_str(), recip_0_pub_key.length(), NULL);
    assert (status == PEP_STATUS_OK);
    status = import_key(session, pub_extra_key_0.c_str(), pub_extra_key_0.length(), NULL);
    assert (status == PEP_STATUS_OK);
    status = import_key(session, pub_extra_key_1.c_str(), pub_extra_key_1.length(), NULL);
    assert (status == PEP_STATUS_OK);

    cout << "Keys imported." << endl;

    pEp_identity* me_recip_1 = new_identity("reencrypt_recip@darthmama.cool", fpr_own_recip_key, PEP_OWN_USERID, "Me Recipient");
    pEp_identity* me_recip_2 = new_identity("reencrypt_recip_numero_deux_test@darthmama.org", fpr_own_recip_2_key, PEP_OWN_USERID, "Me Recipient");
    
    cout << "Inserting own identities and keys into database." << endl;
    status = set_own_key(session, me_recip_1, fpr_own_recip_key);
    assert(status == PEP_STATUS_OK);
    status = set_own_key(session, me_recip_2, fpr_own_recip_2_key);
    assert(status == PEP_STATUS_OK);
    cout << "Done: inserting own identities and keys into database." << endl;

    const string to_reencrypt_from_enigmail = slurp("test_mails/reencrypt_sent_by_enigmail.eml");
    const string to_reencrypt_from_enigmail_BCC = slurp("test_mails/reencrypt_BCC_sent_by_enigmail.eml");
    const string to_reencrypt_from_pEp = slurp("test_mails/reencrypt_encrypted_through_pEp.eml");

    cout << "Calling MIME_decrypt_message with reencrypt flag set on message sent from enigmail with no extra keys." << endl;
    
    char* decrypted_text = nullptr;
    
    // In: extra keys; Out: keys that were used to encrypt this.
    stringlist_t* keys = NULL;
    PEP_decrypt_flags_t flags;
    PEP_rating rating;

    flags = PEP_decrypt_flag_untrusted_server;
    
    status = MIME_decrypt_message(session,
                                  to_reencrypt_from_enigmail.c_str(),
                                  to_reencrypt_from_enigmail.size(),
                                  &decrypted_text,
                                  &keys,
                                  &rating,
                                  &flags);

    cout << decrypted_text << endl;

    cout << "Status is " << tl_status_string(status) << endl;
    assert(decrypted_text);
    assert(rating);

    free(decrypted_text);
    decrypted_text = nullptr;

    cout << "Calling MIME_decrypt_message with reencrypt flag set on message sent from enigmail extra keys." << endl;
        
    // In: extra keys; Out: keys that were used to encrypt this.
    free_stringlist(keys);
    keys = new_stringlist(fpr_pub_extra_key_0);
    stringlist_add(keys, fpr_pub_extra_key_1);    

    flags = PEP_decrypt_flag_untrusted_server;
    
    status = MIME_decrypt_message(session,
                                  to_reencrypt_from_enigmail.c_str(),
                                  to_reencrypt_from_enigmail.size(),
                                  &decrypted_text,
                                  &keys,
                                  &rating,
                                  &flags);

    cout << decrypted_text << endl;
    cout << "Status is " << tl_status_string(status) << endl;


    assert(decrypted_text);
    assert(rating);

    free(decrypted_text);
    decrypted_text = nullptr;


    cout << "Calling MIME_decrypt_message with reencrypt flag set on message sent with recip 2 in BCC from enigmail with no extra keys." << endl;

    free_stringlist(keys);
    keys = NULL;

    flags = PEP_decrypt_flag_untrusted_server;
    
    status = MIME_decrypt_message(session,
                                  to_reencrypt_from_enigmail.c_str(),
                                  to_reencrypt_from_enigmail.size(),
                                  &decrypted_text,
                                  &keys,
                                  &rating,
                                  &flags);

    cout << decrypted_text << endl;
    cout << "Status is " << tl_status_string(status) << endl;


    assert(decrypted_text);
    assert(rating);

    free(decrypted_text);
    decrypted_text = nullptr;


    cout << "Calling MIME_decrypt_message with reencrypt flag set on message sent with recip 2 in BCC from enigmail with extra keys." << endl;

    free_stringlist(keys);
    keys = new_stringlist(fpr_pub_extra_key_0);
    stringlist_add(keys, fpr_pub_extra_key_1);    

    flags = PEP_decrypt_flag_untrusted_server;
    
    status = MIME_decrypt_message(session,
                                  to_reencrypt_from_enigmail.c_str(),
                                  to_reencrypt_from_enigmail.size(),
                                  &decrypted_text,
                                  &keys,
                                  &rating,
                                  &flags);

    cout << decrypted_text << endl;
    cout << "Status is " << tl_status_string(status) << endl;


    assert(decrypted_text);
    assert(rating);

    free(decrypted_text);
    decrypted_text = nullptr;



    cout << "Calling MIME_decrypt_message with reencrypt flag set on message generated by pEp (message 2.0) with no extra keys." << endl;
    free_stringlist(keys);
    keys = NULL;

    flags = PEP_decrypt_flag_untrusted_server;
    
    status = MIME_decrypt_message(session,
                                  to_reencrypt_from_enigmail.c_str(),
                                  to_reencrypt_from_enigmail.size(),
                                  &decrypted_text,
                                  &keys,
                                  &rating,
                                  &flags);

    cout << decrypted_text << endl;
    cout << "Status is " << tl_status_string(status) << endl;


    assert(decrypted_text);
    assert(rating);

    free(decrypted_text);
    decrypted_text = nullptr;

    cout << "Calling MIME_decrypt_message with reencrypt flag set on message generated by pEp (message 2.0) with extra keys." << endl;

    free_stringlist(keys);
    keys = new_stringlist(fpr_pub_extra_key_0);
    stringlist_add(keys, fpr_pub_extra_key_1);    

    flags = PEP_decrypt_flag_untrusted_server;
    
    status = MIME_decrypt_message(session,
                                  to_reencrypt_from_enigmail.c_str(),
                                  to_reencrypt_from_enigmail.size(),
                                  &decrypted_text,
                                  &keys,
                                  &rating,
                                  &flags);

    cout << decrypted_text << endl;
    cout << "Status is " << tl_status_string(status) << endl;


    assert(decrypted_text);
    assert(rating);

    free(decrypted_text);
    decrypted_text = nullptr;

    // message* decrypted_msg = nullptr;
    // stringlist_t* keylist_used = nullptr;
    // 
    // PEP_rating rating;
    // PEP_decrypt_flags_t flags;
    // 
    // flags = 0;
    // status = decrypt_message(session, encrypted_msg, &decrypted_msg, &keylist_used, &rating, &flags);
    // assert(decrypted_msg);
    // assert(keylist_used);
    // assert(rating);
    // assert(status == PEP_DECRYPTED && rating == PEP_rating_unreliable);
    // PEP_comm_type ct = encrypted_msg->from->comm_type;
    // assert(ct == PEP_ct_pEp || ct == PEP_ct_pEp_unconfirmed || ct == PEP_ct_OpenPGP || ct == PEP_ct_OpenPGP_unconfirmed );
    // 
    // cout << "keys used:\n";
    // 
    // int i = 0;
    // 
    // for (stringlist_t* kl4 = keylist_used; kl4 && kl4->value; kl4 = kl4->next, i++)
    // {
    //     if (i == 0)
    //         assert(strcasecmp("",kl4->value) == 0);
    //     else {
    //         cout << "\t " << kl4->value << endl;
    //         assert(strcasecmp("4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", kl4->value) == 0);
    //         cout << "Encrypted for Alice! Yay! It worked!" << endl;
    //     }
    //     assert(i < 2);
    // }
    // cout << "Encrypted ONLY for Alice! Test passed. Move along. These are not the bugs you are looking for." << endl;
 
    // cout << "freeing messages…\n";
    // free_message(encrypted_msg);
    // free_message(decrypted_msg);
    // free_stringlist (keylist_used);
    // cout << "done.\n";
    // 
    // cout << "Now encrypt for self with extra keys." << endl;
    // stringlist_t* extra_keys = new_stringlist(gabrielle_fpr);
    // stringlist_add(extra_keys, bella_fpr);
    // encrypted_msg = NULL;
    // decrypted_msg = NULL;
    // keylist_used = NULL;
    // 
    // cout << "calling encrypt_message_for_identity()\n";
    // status = encrypt_message_for_self(session, alice, outgoing_message, extra_keys, &encrypted_msg, PEP_enc_PGP_MIME, PEP_encrypt_flag_force_unsigned | PEP_encrypt_flag_force_no_attached_key);
    // cout << "encrypt_message() returns " << std::hex << status << '.' << endl;
    // assert(status == PEP_STATUS_OK);
    // assert(encrypted_msg);
    // cout << "message encrypted.\n";
    // 
    // flags = 0;
    // status = decrypt_message(session, encrypted_msg, &decrypted_msg, &keylist_used, &rating, &flags);
    // assert(decrypted_msg);
    // assert(keylist_used);
    // assert(rating);
    // assert(status == PEP_DECRYPTED && rating == PEP_rating_unreliable);
    // ct = encrypted_msg->from->comm_type;
    // assert(ct == PEP_ct_pEp || ct == PEP_ct_pEp_unconfirmed || ct == PEP_ct_OpenPGP || ct == PEP_ct_OpenPGP_unconfirmed );
    // 
    // cout << "keys used:\n";
    // 
    // for (stringlist_t* incoming_kl = extra_keys; incoming_kl && incoming_kl->value; incoming_kl = incoming_kl->next) {
    //     bool found = false;
    //     cout << "Encrypted for: ";
    //     for (stringlist_t* kl4 = keylist_used; kl4 && kl4->value; kl4 = kl4->next, i++) {
    //         if (strcasecmp(incoming_kl->value, kl4->value) == 0) {
    //             cout << "\t " << kl4->value;
    //             found = true;
    //             break;
    //         }
    //     }
    //     cout << endl;
    //     assert(found);
    // }
    // cout << "Encrypted for all the extra keys!" << endl;
    // 
    // bool found = false;
    // for (stringlist_t* kl4 = keylist_used; kl4 && kl4->value; kl4 = kl4->next)
    // {
    //     if (strcasecmp(alice_fpr, kl4->value) == 0) {
    //         found = true;
    //         cout << "Encrypted also for Alice! Yay!" << endl;
    //         break;
    //     }
    // }
    // assert(found);
    // 
    // free_message(encrypted_msg);
    // encrypted_msg = NULL;
    // free_message(decrypted_msg);
    // decrypted_msg = NULL;
    // free_stringlist(keylist_used);
    // keylist_used = NULL;
    // 
    // cout << "Now add a bad fpr." << endl;
    // 
    // stringlist_add(extra_keys, nobody_fpr);
    // 
    // cout << "calling encrypt_message_for_identity()\n";
    // status = encrypt_message_for_self(session, alice, outgoing_message, extra_keys, &encrypted_msg, PEP_enc_PGP_MIME, PEP_encrypt_flag_force_unsigned | PEP_encrypt_flag_force_no_attached_key);
    // cout << "encrypt_message() returns " << std::hex << status << '.' << endl;
    // assert(status != PEP_STATUS_OK);
    // 
    // free_message(outgoing_message);
    // outgoing_message = NULL;
    // free_message(encrypted_msg);
    // encrypted_msg = NULL;
    // free_message(decrypted_msg);
    // decrypted_msg = NULL;
    // free_stringlist(keylist_used);
    // keylist_used = NULL;
    // 
    // 
    // cout << "*** Now testing MIME_encrypt_for_self ***" << endl;
    // 
    // alice = new_identity("pep.test.alice@pep-project.org", NULL, PEP_OWN_USERID, "Alice Test");
    // bob = new_identity("pep.test.bob@pep-project.org", NULL, "42", "Bob Test");
    // 
    // cout << "Reading in alice_bob_encrypt_test_plaintext_mime.eml..." << endl;
    // 
    // const string mimetext = slurp("test_mails/alice_bob_encrypt_test_plaintext_mime.eml");
    // 
    // cout << "Text read:" << endl;
    // cout << mimetext.c_str() << endl;
    // char* encrypted_mimetext = nullptr;
    // 
    // cout << "Calling MIME_encrypt_message_for_self" << endl;
    // status = MIME_encrypt_message_for_self(session, alice, mimetext.c_str(),
    //                                        mimetext.size(), 
    //                                        NULL,
    //                                        &encrypted_mimetext, 
    //                                        PEP_enc_PGP_MIME, 
    //                                        PEP_encrypt_flag_force_unsigned | PEP_encrypt_flag_force_no_attached_key);
    // 
    // cout << "Encrypted message:" << endl;
    // cout << encrypted_mimetext << endl;
    // 
    // cout << "Calling MIME_decrypt_message" << endl;
    // 
    // char* decrypted_mimetext = nullptr;
    // free_stringlist(keylist_used);
    // keylist_used = nullptr;
    // PEP_decrypt_flags_t mimeflags;
    // PEP_rating mimerating;
    // 
    // mimeflags = 0;
    // status = MIME_decrypt_message(session,
    //                               encrypted_mimetext,
    //                               strlen(encrypted_mimetext),
    //                               &decrypted_mimetext,
    //                               &keylist_used,
    //                               &mimerating,
    //                               &mimeflags);
    // 
    // assert(decrypted_mimetext);
    // assert(keylist_used);
    // assert(mimerating);
    //                          
    // assert(status == PEP_DECRYPTED && mimerating == PEP_rating_unreliable);
    // 
    // cout << "Decrypted message:" << endl;
    // cout << decrypted_mimetext << endl;
    // 
    // cout << "keys used:\n";
    // 
    // i = 0;
    // 
    // for (stringlist_t* kl4 = keylist_used; kl4 && kl4->value; kl4 = kl4->next, i++)
    // {
    //     if (i == 0)
    //         assert(strcasecmp("",kl4->value) == 0);
    //     else {
    //         cout << "\t " << kl4->value << endl;
    //         assert(strcasecmp("4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", kl4->value) == 0);
    //         cout << "Encrypted for Alice! Yay! It worked!" << endl;
    //     }
    //     assert(i < 2);
    // }
    // cout << "Encrypted ONLY for Alice! Test passed. Move along. These are not the bugs you are looking for." << endl;
    
    cout << "calling release()\n";
    release(session);
    return 0;
}
