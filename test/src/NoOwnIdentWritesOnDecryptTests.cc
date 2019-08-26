// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <cstring>
#include <cpptest.h>

#include "pEpEngine.h"
#include "test_util.h"

#include "EngineTestIndividualSuite.h"
#include "NoOwnIdentWritesOnDecryptTests.h"

using namespace std;

NoOwnIdentWritesOnDecryptTests::NoOwnIdentWritesOnDecryptTests(string suitename, string test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir) {
    _to_decrypt = NULL;
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("NoOwnIdentWritesOnDecryptTests::check_no_own_ident_writes_on_decrypt"),
                                                                      static_cast<Func>(&NoOwnIdentWritesOnDecryptTests::check_no_own_ident_writes_on_decrypt)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("NoOwnIdentWritesOnDecryptTests::check_address_only_no_overwrite"),
                                                                      static_cast<Func>(&NoOwnIdentWritesOnDecryptTests::check_address_only_no_overwrite)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("NoOwnIdentWritesOnDecryptTests::check_full_info_no_overwrite"),
                                                                      static_cast<Func>(&NoOwnIdentWritesOnDecryptTests::check_full_info_no_overwrite)));
}

NoOwnIdentWritesOnDecryptTests::~NoOwnIdentWritesOnDecryptTests() {
    free_message(_to_decrypt);
}

void NoOwnIdentWritesOnDecryptTests::check_no_own_ident_writes_on_decrypt() {
    // This is a weird case - it is NOT a test case, it's just abusing the environment to
    // set _to_decrypt without polluting test keyrings for later tests.
    message* msg = new_message(PEP_dir_outgoing);
    pEp_identity* sender = NULL;
    pEp_identity* me_recip = NULL;
    pEp_identity* other_recip = NULL;
    
    TEST_ASSERT(slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc"));
    TEST_ASSERT(slurp_and_import_key(session, "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc"));	
    TEST_ASSERT(slurp_and_import_key(session, "test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc"));
    TEST_ASSERT(slurp_and_import_key(session, "test_keys/pub/pep-test-carol-0x42A85A42_pub.asc"));
    
    sender = new_identity("pep.test.alice@pep-project.org", NULL, PEP_OWN_USERID, "Alice");
    set_own_key(session, sender, "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97");
    myself(session, sender);
    
    me_recip = new_identity("pep.test.bob@pep-project.org", NULL, "Bob_is_hot", "Hot Bob");
    other_recip = new_identity("pep-test-carol@pep-project.org", NULL, "Carol_loves_me", "Carol Loves Alice");

    identity_list* to_list = new_identity_list(other_recip);
    identity_list_add(to_list, me_recip);
    
    msg->from = sender;
    msg->to = to_list;
    
    msg->shortmsg = strdup("just a message");
    msg->longmsg = strdup("a really dumb message");
    
    message* enc_msg = NULL;
    
    PEP_STATUS status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    TEST_ASSERT(status == PEP_STATUS_OK);
    free_message(msg);
    enc_msg->dir = PEP_dir_incoming;
    _to_decrypt = enc_msg;
    TEST_ASSERT(true);
}

void NoOwnIdentWritesOnDecryptTests::check_address_only_no_overwrite() {
    TEST_ASSERT(_to_decrypt);
    message* copy = message_dup(_to_decrypt);

    free_identity(copy->from);
    
    TEST_ASSERT(slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc"));
    TEST_ASSERT(slurp_and_import_key(session, "test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc"));
    TEST_ASSERT(slurp_and_import_key(session, "test_keys/priv/pep-test-bob-0xC9C2EE39_priv.asc"));
    TEST_ASSERT(slurp_and_import_key(session, "test_keys/pub/pep-test-carol-0x42A85A42_pub.asc"));
    
    const char* bob_name = "STOP MESSING WITH ME ALICE";
    const char* bob_fpr = "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39";
    pEp_identity* me = new_identity("pep.test.bob@pep-project.org", NULL, PEP_OWN_USERID, bob_name);
    PEP_STATUS status = set_own_key(session, me, bob_fpr);
    TEST_ASSERT(status == PEP_STATUS_OK);
    status = myself(session, me);
    TEST_ASSERT(status == PEP_STATUS_OK);
    free_identity(me);
    me = NULL;
    
    copy->from = new_identity("pep.test.alice@pep-project.org", NULL, NULL, NULL);
    pEp_identity* bob_ident = copy->to->next->ident;
    free(bob_ident->fpr);
    free(bob_ident->user_id);
    bob_ident->fpr = NULL;
    bob_ident->user_id = NULL;
    
    // yes, I know the test keeps the "old" user_id for carol, but it's irrelevant here/

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_decrypt_flags_t flags = 0;
    PEP_rating rating = PEP_rating_undefined;
    
    status = decrypt_message(session, copy, &dec_msg, &keylist, &rating, &flags);    
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(strcmp(dec_msg->to->next->ident->username, "Hot Bob") == 0);
    
    // Make sure Alice calling Bob hot doesn't infiltrate his DB
    status = get_identity(session, "pep.test.bob@pep-project.org", PEP_OWN_USERID, &me);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(me);
    TEST_ASSERT(strcmp(me->username, bob_name) == 0);
    TEST_ASSERT(strcmp(me->fpr, bob_fpr) == 0);
    free_identity(me);
    free_message(dec_msg);
    free_message(copy);
}

void NoOwnIdentWritesOnDecryptTests::check_full_info_no_overwrite() {
    TEST_ASSERT(_to_decrypt);
    message* copy = message_dup(_to_decrypt);

    free_identity(copy->from);
    
    TEST_ASSERT(slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc"));
    TEST_ASSERT(slurp_and_import_key(session, "test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc"));
    TEST_ASSERT(slurp_and_import_key(session, "test_keys/priv/pep-test-bob-0xC9C2EE39_priv.asc"));
    TEST_ASSERT(slurp_and_import_key(session, "test_keys/pub/pep-test-carol-0x42A85A42_pub.asc"));
    
    const char* bob_name = "STOP MESSING WITH ME ALICE";
    const char* bob_fpr = "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39";
    pEp_identity* me = new_identity("pep.test.bob@pep-project.org", NULL, PEP_OWN_USERID, bob_name);
    PEP_STATUS status = set_own_key(session, me, bob_fpr);
    TEST_ASSERT(status == PEP_STATUS_OK);
    status = myself(session, me);
    TEST_ASSERT(status == PEP_STATUS_OK);
    free_identity(me);
    me = NULL;
    
    copy->from = new_identity("pep.test.alice@pep-project.org", NULL, NULL, NULL);
    pEp_identity* bob_ident = copy->to->next->ident;
    free(bob_ident->user_id);
    bob_ident->user_id = strdup(PEP_OWN_USERID);
    bob_ident->me = true;
    
    // yes, I know the test keeps the "old" user_id for carol, but it's irrelevant here
    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_decrypt_flags_t flags = 0;
    PEP_rating rating = PEP_rating_undefined;
    
    status = decrypt_message(session, copy, &dec_msg, &keylist, &rating, &flags);    
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(strcmp(dec_msg->to->next->ident->username, "Hot Bob") == 0);
    
    // Make sure Alice calling Bob hot doesn't infiltrate his DB
    status = get_identity(session, "pep.test.bob@pep-project.org", PEP_OWN_USERID, &me);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(me);
    TEST_ASSERT(strcmp(me->username, bob_name) == 0);
    TEST_ASSERT(strcmp(me->fpr, bob_fpr) == 0);
    free_identity(me);
    free_message(dec_msg);

    free_message(copy);
}
