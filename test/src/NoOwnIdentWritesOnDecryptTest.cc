// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <cstring>

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "TestUtilities.h"



#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for NoOwnIdentWritesOnDecryptTest
    class NoOwnIdentWritesOnDecryptTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;
            message* _to_decrypt;
            string test_path;            
            std::vector<std::pair<std::string, std::string>> init_files;
            
        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            NoOwnIdentWritesOnDecryptTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
                _to_decrypt = NULL;
            }

            ~NoOwnIdentWritesOnDecryptTest() override {
                // You can do clean-up work that doesn't throw exceptions here.
                free_message(_to_decrypt);
            }

            // If the constructor and destructor are not enough for setting up
            // and cleaning up each test, you can define the following methods:

            void SetUp() override {
                // Code here will be called immediately after the constructor (right
                // before each test).

                // Leave this empty if there are no files to copy to the home directory path
                init_files = std::vector<std::pair<std::string, std::string>>();

                // Get a new test Engine.
                engine = new Engine(test_path);
                ASSERT_NOTNULL(engine);

                // Ok, let's initialize test directories etc.
                engine->prep(NULL, NULL, NULL, init_files);

                // Ok, try to start this bugger.
                engine->start();
                ASSERT_NOTNULL(engine->session);
                session = engine->session;

                // Engine is up. Keep on truckin'
            }

            void TearDown() override {
                // Code here will be called immediately after each test (right
                // before the destructor).
                engine->shut_down();
                delete engine;
                engine = NULL;
                session = NULL;
            }

        private:
            const char* test_suite_name;
            const char* test_name;
            // Objects declared here can be used by all tests in the NoOwnIdentWritesOnDecryptTest suite.

    };

}  // namespace


TEST_F(NoOwnIdentWritesOnDecryptTest, check_no_own_ident_writes_on_decrypt) {
    
    // set _to_decrypt without polluting test keyrings
    message* msg = new_message(PEP_dir_outgoing);
    pEp_identity* sender = NULL;
    pEp_identity* me_recip = NULL;
    pEp_identity* other_recip = NULL;

    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc"));
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc"));
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc"));
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep-test-carol-0x42A85A42_pub.asc"));

    sender = new_identity("pep.test.alice@pep-project.org", NULL, PEP_OWN_USERID, "Alice");
    set_own_key(session, sender, "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97");
    myself(session, sender);

    me_recip = new_identity("pep.test.bob@pep-project.org", NULL, "Bob_is_hot", "Hot Bob");
    other_recip = new_identity("pep-test-carol@pep-project.org", NULL, "Carol_loves_me", "Carol Loves Alice");

    // Better set those default fprs
    const char* bob_fpr = "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39";
    const char* carol_fpr = "8DD4F5827B45839E9ACCA94687BDDFFB42A85A42";

    PEP_STATUS status = set_fpr_preserve_ident(session, me_recip, bob_fpr, true);
    ASSERT_OK;
    status = set_fpr_preserve_ident(session, other_recip, carol_fpr, true);
    ASSERT_OK;

    identity_list* to_list = new_identity_list(other_recip);
    identity_list_add(to_list, me_recip);

    msg->from = sender;
    msg->to = to_list;

    msg->shortmsg = strdup("just a message");
    msg->longmsg = strdup("a really dumb message");

    message* enc_msg = NULL;

    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_OK;
    free_message(msg);
    enc_msg->dir = PEP_dir_incoming;
    _to_decrypt = enc_msg;
    
    engine->shut_down();
    delete engine;

    // New Engine, new test case:
    engine = new Engine(test_path);
    ASSERT_NOTNULL(engine);

    // Ok, let's initialize test directories etc.
    engine->prep(NULL, NULL, NULL, init_files);

    // Ok, try to start this bugger.
    engine->start();
    ASSERT_NOTNULL(engine->session);
    session = engine->session;

    // Next test: check_address_only_no_overwrite) {
    ASSERT_NOTNULL(_to_decrypt);
    message* copy = message_dup(_to_decrypt);

    free_identity(copy->from);

    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc"));
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc"));
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/priv/pep-test-bob-0xC9C2EE39_priv.asc"));
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep-test-carol-0x42A85A42_pub.asc"));

    const char* bob_name = "STOP MESSING WITH ME ALICE";
    pEp_identity* me = new_identity("pep.test.bob@pep-project.org", NULL, PEP_OWN_USERID, bob_name);
    status = set_own_key(session, me, bob_fpr);
    ASSERT_OK;
    status = myself(session, me);
    ASSERT_OK;
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

    status = decrypt_message(session, copy, &dec_msg, &keylist, &flags);
    ASSERT_OK;
    ASSERT_STREQ(dec_msg->to->next->ident->username, "Hot Bob");

    // Make sure Alice calling Bob hot doesn't infiltrate his DB
    status = get_identity(session, "pep.test.bob@pep-project.org", PEP_OWN_USERID, &me);
    ASSERT_OK;
    ASSERT_NOTNULL(me);
    ASSERT_STREQ(me->username, bob_name);
    ASSERT_STREQ(me->fpr, bob_fpr);
    free_identity(me);
    free_message(dec_msg);
    free_message(copy);
    copy = NULL;
    
    engine->shut_down();
    delete engine;

    // New Engine, new test case:
    engine = new Engine(test_path);
    ASSERT_NOTNULL(engine);

    // Ok, let's initialize test directories etc.
    engine->prep(NULL, NULL, NULL, init_files);

    // Ok, try to start this bugger.
    engine->start();
    ASSERT_NOTNULL(engine->session);
    session = engine->session;

    // Next test case: check_full_info_no_overwrite) {
    ASSERT_NOTNULL(_to_decrypt);
    copy = message_dup(_to_decrypt);

    free_identity(copy->from);

    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc"));
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc"));
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/priv/pep-test-bob-0xC9C2EE39_priv.asc"));
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep-test-carol-0x42A85A42_pub.asc"));

    me = new_identity("pep.test.bob@pep-project.org", NULL, PEP_OWN_USERID, bob_name);
    status = set_own_key(session, me, bob_fpr);
    ASSERT_OK;
    status = myself(session, me);
    ASSERT_OK;
    free_identity(me);
    me = NULL;

    copy->from = new_identity("pep.test.alice@pep-project.org", NULL, NULL, NULL);
    bob_ident = copy->to->next->ident;
    free(bob_ident->user_id);
    bob_ident->user_id = strdup(PEP_OWN_USERID);
    bob_ident->me = true;

    // yes, I know the test keeps the "old" user_id for carol, but it's irrelevant here
    dec_msg = NULL;
    keylist = NULL;
    flags = 0;

    status = decrypt_message(session, copy, &dec_msg, &keylist, &flags);
    ASSERT_OK;
    ASSERT_STREQ(dec_msg->to->next->ident->username, "Hot Bob");

    // Make sure Alice calling Bob hot doesn't infiltrate his DB
    status = get_identity(session, "pep.test.bob@pep-project.org", PEP_OWN_USERID, &me);
    ASSERT_OK;
    ASSERT_NOTNULL(me);
    ASSERT_STREQ(me->username, bob_name);
    ASSERT_STREQ(me->fpr, bob_fpr);
    free_identity(me);
    free_message(dec_msg);

    free_message(copy);
}
