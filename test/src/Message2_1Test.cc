// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <cstring>
#include <string>

#include "test_util.h"
#include "TestConstants.h"

#include "pEpEngine.h"
#include "pEp_internal.h"

#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for Message2_1Test
    class Message2_1Test : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            Message2_1Test() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~Message2_1Test() override {
                // You can do clean-up work that doesn't throw exceptions here.
            }

            // If the constructor and destructor are not enough for setting up
            // and cleaning up each test, you can define the following methods:

            void SetUp() override {
                // Code here will be called immediately after the constructor (right
                // before each test).

                // Leave this empty if there are no files to copy to the home directory path
                std::vector<std::pair<std::string, std::string>> init_files = std::vector<std::pair<std::string, std::string>>();

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

            bool verify_message_version_produced(message* enc_msg, unsigned int* maj_inout, unsigned int* min_inout) {
                if (!maj_inout || !min_inout)
                    return false;
                int major = *maj_inout;
                int minor = *min_inout;

                char* ptext = NULL;
                size_t psize = 0;
                stringlist_t* keylist = NULL;

                PEP_STATUS status = decrypt_and_verify(session, enc_msg->attachments->next->value,
                                                       enc_msg->attachments->next->size, NULL, 0,
                                                       &ptext, &psize, &keylist,
                                                       NULL);

                output_stream << ptext << endl;

                // fixme, check status
                if (strstr(ptext, "pEp-Wrapped-Message-Info: OUTER") != NULL && strstr(ptext, "pEp-Wrapped-Message-Info: INNER") != NULL) {
                    *maj_inout = 2;
                    *min_inout = 0;
                }
                else if (strstr(ptext, "X-pEp-Wrapped-Message-Info: INNER") != NULL && strstr(ptext, "forwarded=\"no\"") != NULL) {
                    *maj_inout = 2;
                    *min_inout = 1;
                }
                else {
                    *maj_inout = 1;
                    *min_inout = 0;
                }

                switch (major) {
                    case 1:
                        if (*maj_inout == 1)
                            return true;
                        return false;
                    case 2:
                        if (*maj_inout != 2)
                            return false;
                        if (*min_inout == minor)
                            return true;
                        return false;
                    default:
                        *maj_inout = 0;
                        *min_inout = 0;
                        return false;
                }
            }

        private:
            const char* test_suite_name;
            const char* test_name;
            string test_path;
            // Objects declared here can be used by all tests in the Message2_1Test suite.

    };

}  // namespace



TEST_F(Message2_1Test, check_message2_1_recip_2_0) {

    pEp_identity* alice = NULL;
    pEp_identity* carol = NULL;

    PEP_STATUS status = set_up_preset(session, ALICE,
                                      true, true, true, true, true, true, &alice);

    ASSERT_OK;
    ASSERT_NOTNULL(alice);

    status = set_up_preset(session, CAROL,
                           true, true, true, false, false, false, &carol);

    ASSERT_OK;
    ASSERT_NOTNULL(carol);

    // default should be 2.0 after setting pep status
    status = update_identity(session, carol);
    ASSERT_OK;
    ASSERT_EQ(carol->major_ver , 2);
    ASSERT_EQ(carol->minor_ver , 0);
    // generate message
    pEp_identity* carol_to = new_identity(carol->address, NULL, NULL, NULL);

    message* msg = new_message(PEP_dir_outgoing);

    msg->from = alice;
    msg->to = new_identity_list(carol_to);
    msg->shortmsg = strdup("Boom shaka laka");
    msg->longmsg = strdup("Don't you get sick of these?");

    message* enc_msg = NULL;

    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_OK;

    // ensure sent message is in 2.0 format
    unsigned int major = 2;
    unsigned int minor = 0;
    ASSERT_TRUE(verify_message_version_produced(enc_msg, &major, &minor));

    free_identity(carol);
    free_message(msg);
    free_message(enc_msg);
}

/* PEP_STATUS set_up_preset(PEP_SESSION session,
                         pEp_test_ident_preset preset_name,
                         bool set_ident,
                         bool set_pep,
                         bool trust,
                         bool set_own,
                         bool setup_private,
                         pEp_identity** ident) {
*/

TEST_F(Message2_1Test, check_message2_1_recip_OpenPGP) {
    // set recip to 1.0
    pEp_identity* alice = NULL;
    pEp_identity* carol = NULL;

    PEP_STATUS status = set_up_preset(session, ALICE,
                                      true, true, true, true, true, true, &alice);

    ASSERT_OK;
    ASSERT_NOTNULL(alice);

    status = set_up_preset(session, CAROL,
                           true, true, false, false, false, false, &carol);

    ASSERT_OK;
    ASSERT_NOTNULL(carol);

    status = update_identity(session, carol);
    ASSERT_OK;
    ASSERT_LT(carol->major_ver , 2);
    ASSERT_EQ(carol->minor_ver , 0);

    // generate message
    pEp_identity* carol_to = new_identity(carol->address, NULL, NULL, NULL);

    message* msg = new_message(PEP_dir_outgoing);

    msg->from = alice;
    msg->to = new_identity_list(carol_to);
    msg->shortmsg = strdup("Boom shaka laka");
    msg->longmsg = strdup("Don't you get sick of these?");

    message* enc_msg = NULL;

    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_OK;

    // ensure sent message is in 1.0 format
    unsigned int major = 1;
    unsigned int minor = 0;
    ASSERT_TRUE(verify_message_version_produced(enc_msg, &major, &minor));

    free_identity(carol);
    free_message(msg);
    free_message(enc_msg);
}

TEST_F(Message2_1Test, check_message2_1_recip_2_1) {
    // set recip to 2.1

    pEp_identity* alice = NULL;
    pEp_identity* carol = NULL;

    PEP_STATUS status = set_up_preset(session, ALICE,
                                      true, true, true, true, true, true, &alice);

    ASSERT_OK;
    ASSERT_NOTNULL(alice);

    status = set_up_preset(session, CAROL,
                           true, true, true, false, false, false, &carol);

    ASSERT_OK;
    ASSERT_NOTNULL(carol);

    status = set_pEp_version(session, carol, 2, 1);

    // default should be 2.1 after setting pep status
    status = update_identity(session, carol);
    ASSERT_OK;
    ASSERT_EQ(carol->major_ver , 2);
    ASSERT_EQ(carol->minor_ver , 1);
    // generate message
    pEp_identity* carol_to = new_identity(carol->address, NULL, NULL, NULL);

    message* msg = new_message(PEP_dir_outgoing);

    msg->from = alice;
    msg->to = new_identity_list(carol_to);
    msg->shortmsg = strdup("Boom shaka laka");
    msg->longmsg = strdup("Don't you get sick of these?");

    message* enc_msg = NULL;

    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_OK;

    // ensure sent message is in 2.0 format
    unsigned int major = 2;
    unsigned int minor = 1;
    ASSERT_TRUE(verify_message_version_produced(enc_msg, &major, &minor));

    free_identity(carol);
    free_message(msg);
    free_message(enc_msg);
}

TEST_F(Message2_1Test, check_message2_1_recip_1_0_from_msg_OpenPGP) {
    pEp_identity* alex = NULL;

    PEP_STATUS status = set_up_preset(session, ALEX_0,
                                      true, true, true, true, true, true, &alex);

    ASSERT_OK;
    ASSERT_NOTNULL(alex);

    // receive 1.0 message from OpenPGP
    string incoming = slurp("test_mails/From_M1_0.eml");

    char* dec_msg;
    char* mod_src = NULL;
    PEP_decrypt_flags_t flags = 0;
    stringlist_t* keylist_used = NULL;
    PEP_rating rating;

    status = MIME_decrypt_message(session, incoming.c_str(), incoming.size(), &dec_msg, &keylist_used, &rating, &flags, &mod_src);

    ASSERT_OK;
    // generate message

    message* msg = new_message(PEP_dir_outgoing);

    msg->from = alex;
    msg->to = new_identity_list(new_identity("pep-test-carol@pep-project.org", NULL, NULL, NULL));
    msg->shortmsg = strdup("Boom shaka laka");
    msg->longmsg = strdup("Don't you get sick of these?");

    message* enc_msg = NULL;

    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_OK;

    // ensure sent message is in 1.0 format
    unsigned int major = 1;
    unsigned int minor = 0;
    ASSERT_TRUE(verify_message_version_produced(enc_msg, &major, &minor));

    free_message(msg);
    free_message(enc_msg);
    free(dec_msg);
    free(mod_src);
}

TEST_F(Message2_1Test, check_message2_1_recip_2_0_from_msg) {
    // receive 2.0 message
    pEp_identity* carol = NULL;

    PEP_STATUS status = set_up_preset(session, CAROL,
                                      true, true, true, true, true, true, &carol);

    ASSERT_OK;
    ASSERT_NOTNULL(carol);

    // receive 1.0 message from OpenPGP
    string incoming = slurp("test_mails/2_0_msg.eml");

    char* dec_msg;
    char* mod_src = NULL;
    PEP_decrypt_flags_t flags = 0;
    stringlist_t* keylist_used = NULL;
    PEP_rating rating;

    status = MIME_decrypt_message(session, incoming.c_str(), incoming.size(), &dec_msg, &keylist_used, &rating, &flags, &mod_src);

    ASSERT_OK;
    // generate message

    message* msg = new_message(PEP_dir_outgoing);

    msg->from = carol;
    msg->to = new_identity_list(new_identity("pep.test.alice@pep-project.org", NULL, NULL, NULL));
    msg->shortmsg = strdup("Boom shaka laka");
    msg->longmsg = strdup("Don't you get sick of these?");

    message* enc_msg = NULL;

    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_OK;

    // ensure sent message is in 1.0 format
    unsigned int major = 2;
    unsigned int minor = 0;
    ASSERT_TRUE(verify_message_version_produced(enc_msg, &major, &minor));

    free_message(msg);
    free_message(enc_msg);
    free(dec_msg);
    free(mod_src);
}

TEST_F(Message2_1Test, check_message2_1_recip_2_1_from_msg) {
    // receive 2.1 message
    pEp_identity* carol = NULL;

    PEP_STATUS status = set_up_preset(session, CAROL,
                                      true, true, true, true, true, true, &carol);

    ASSERT_OK;
    ASSERT_NOTNULL(carol);

    // receive 1.0 message from OpenPGP
    string incoming = slurp("test_mails/From_M2_1.eml");

    char* dec_msg;
    char* mod_src = NULL;
    PEP_decrypt_flags_t flags = 0;
    stringlist_t* keylist_used = NULL;
    PEP_rating rating;

    status = MIME_decrypt_message(session, incoming.c_str(), incoming.size(), &dec_msg, &keylist_used, &rating, &flags, &mod_src);

    ASSERT_OK;
    // generate message

    pEp_identity* alice = new_identity("pep.test.alice@pep-project.org", NULL, NULL, NULL);
    status = update_identity(session, alice);
    ASSERT_OK;
    ASSERT_EQ(alice->comm_type, PEP_ct_pEp_unconfirmed);
    
    message* msg = new_message(PEP_dir_outgoing);

    msg->from = carol;
    msg->to = new_identity_list(new_identity("pep.test.alice@pep-project.org", NULL, NULL, NULL));
    msg->shortmsg = strdup("Boom shaka laka");
    msg->longmsg = strdup("Don't you get sick of these?");

    message* enc_msg = NULL;

    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_OK;

    // ensure sent message is in 2.1 format
    unsigned int major = 2;
    unsigned int minor = 1;
    ASSERT_TRUE(verify_message_version_produced(enc_msg, &major, &minor));

    free_message(msg);
    free_message(enc_msg);
    free(dec_msg);
    free(mod_src);
}

TEST_F(Message2_1Test, check_message2_1_recip_mixed_2_0) {
    // Set mixed recipient values
    pEp_identity* alice = NULL;
    pEp_identity* bob = NULL;
    pEp_identity* carol = NULL;
    pEp_identity* dave = NULL;
    pEp_identity* alex = NULL;

    PEP_STATUS status = set_up_preset(session, ALICE,
                                      true, true, true, true, true, true, &alice);

    ASSERT_OK;
    ASSERT_NOTNULL(alice);

    status = set_up_preset(session, BOB,
                           true, true, true, false, false, false, &bob);

    ASSERT_OK;
    ASSERT_NOTNULL(bob);

    status = set_pEp_version(session, bob, 2, 1);

    // default should be 2.1 after setting pep status
    status = update_identity(session, bob);
    ASSERT_OK;
    ASSERT_EQ(bob->major_ver , 2);
    ASSERT_EQ(bob->minor_ver , 1);

    status = set_up_preset(session, CAROL,
                           true, true, true, false, false, false, &carol);

    ASSERT_OK;
    ASSERT_NOTNULL(carol);

    status = set_pEp_version(session, carol, 2, 1);

    // default should be 2.1 after setting pep status
    status = update_identity(session, carol);
    ASSERT_OK;
    ASSERT_EQ(carol->major_ver , 2);
    ASSERT_EQ(carol->minor_ver , 1);

    status = set_up_preset(session, DAVE,
                           true, true, true, false, false, false, &dave);

    ASSERT_OK;
    ASSERT_NOTNULL(dave);

    status = set_pEp_version(session, dave, 2, 0);

    // default should be 2.1 after setting pep status
    status = update_identity(session, dave);
    ASSERT_OK;
    ASSERT_EQ(dave->major_ver , 2);
    ASSERT_EQ(dave->minor_ver , 0);

    status = set_up_preset(session, ALEX,
                           true, true, true, true, false, false, &alex);

    ASSERT_OK;
    ASSERT_NOTNULL(alex);

    status = set_pEp_version(session, alex, 2, 1);

    // default should be 2.1 after setting pep status
    status = update_identity(session, alex);
    ASSERT_OK;
    ASSERT_EQ(alex->major_ver , 2);
    ASSERT_EQ(alex->minor_ver , 1);

    // generate message
    message* msg = new_message(PEP_dir_outgoing);

    msg->from = alice;
    msg->to = new_identity_list(new_identity(bob->address, NULL, NULL, NULL));
    identity_list_add(msg->to, new_identity(carol->address, NULL, NULL, NULL));
    identity_list_add(msg->to, new_identity(dave->address, NULL, NULL, NULL));
    identity_list_add(msg->to, new_identity(alex->address, NULL, NULL, NULL));
    msg->shortmsg = strdup("Boom shaka laka");
    msg->longmsg = strdup("Don't you get sick of these?");

    message* enc_msg = NULL;

    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_OK;

    // ensure sent message is in 2.0 format
    unsigned int major = 2;
    unsigned int minor = 0;
    ASSERT_TRUE(verify_message_version_produced(enc_msg, &major, &minor));

    free_message(msg);
    free_message(enc_msg);
}

TEST_F(Message2_1Test, check_message2_1_recip_mixed_1_0_OpenPGP) {
    // Set mixed recipient values
    pEp_identity* alice = NULL;
    pEp_identity* bob = NULL;
    pEp_identity* carol = NULL;
    pEp_identity* dave = NULL;
    pEp_identity* alex = NULL;

    PEP_STATUS status = set_up_preset(session, ALICE,
                                      true, true, true, true, true, true, &alice);

    ASSERT_OK;
    ASSERT_NOTNULL(alice);

    status = set_up_preset(session, BOB,
                           true, true, true, false, false, false, &bob);

    ASSERT_OK;
    ASSERT_NOTNULL(bob);

    status = set_pEp_version(session, bob, 2, 1);

    // default should be 2.1 after setting pep status
    status = update_identity(session, bob);
    ASSERT_OK;
    ASSERT_EQ(bob->major_ver , 2);
    ASSERT_EQ(bob->minor_ver , 1);

    status = set_up_preset(session, CAROL,
                           true, true, true, false, false, false, &carol);

    ASSERT_OK;
    ASSERT_NOTNULL(carol);

    status = set_pEp_version(session, carol, 2, 1);

    // default should be 2.1 after setting pep status
    status = update_identity(session, carol);
    ASSERT_OK;
    ASSERT_EQ(carol->major_ver , 2);
    ASSERT_EQ(carol->minor_ver , 1);

    status = set_up_preset(session, DAVE,
                           true, true, true, false, false, false, &dave);

    ASSERT_OK;
    ASSERT_NOTNULL(dave);

    status = set_pEp_version(session, dave, 2, 0);

    // default should be 2.1 after setting pep status
    status = update_identity(session, dave);
    ASSERT_OK;
    ASSERT_EQ(dave->major_ver , 2);
    ASSERT_EQ(dave->minor_ver , 0);

    status = set_up_preset(session, ALEX,
                           true, true, false, true, false, false, &alex);

    ASSERT_OK;
    ASSERT_NOTNULL(alex);

    status = set_pEp_version(session, alex, 1, 0);

    // default should be 1.0 after setting pep status
    status = update_identity(session, alex);
    ASSERT_OK;
    ASSERT_EQ(alex->major_ver , 1);
    ASSERT_EQ(alex->minor_ver , 0);

    // generate message
    message* msg = new_message(PEP_dir_outgoing);

    msg->from = alice;
    msg->to = new_identity_list(new_identity(bob->address, NULL, NULL, NULL));
    identity_list_add(msg->to, new_identity(carol->address, NULL, NULL, NULL));
    identity_list_add(msg->to, new_identity(dave->address, NULL, NULL, NULL));
    identity_list_add(msg->to, new_identity(alex->address, NULL, NULL, NULL));
    msg->shortmsg = strdup("Boom shaka laka");
    msg->longmsg = strdup("Don't you get sick of these?");

    message* enc_msg = NULL;

    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_OK;

    // ensure sent message is in 2.0 format
    unsigned int major = 1;
    unsigned int minor = 0;
    ASSERT_TRUE(verify_message_version_produced(enc_msg, &major, &minor));

    free_message(msg);
    free_message(enc_msg);
}
