#include <stdlib.h>
#include <string>
#include <cstring>

#include "pEpEngine.h"
#include "pEpEngine_internal.h"
#include "TestUtilities.h"
#include "TestConstants.h"
#include "Engine.h"

#include <gtest/gtest.h>

#define GMTMTT_WRITEOUT 0
namespace {

	//The fixture for GenerateMailsToMessageTypeTest
    class GenerateMailsToMessageTypeTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            GenerateMailsToMessageTypeTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~GenerateMailsToMessageTypeTest() override {
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

                // Used in debugger fun in order to force wrong key into mail
                // fpr = 89047BFE779999F77CFBEDB284593ADAC6406F81
                const char* badkeyfile_name = "test_keys/pub/big_clumsy_cat_0xC6406F81_pub.asc";
                slurp_and_import_key(session, badkeyfile_name);
            }

            void TearDown() override {
                // Code here will be called immediately after each test (right
                // before the destructor).
                engine->shut_down();
                delete engine;
                engine = NULL;
                session = NULL;
            }

            message* gen_outgoing_message_template(pEp_identity* from, pEp_identity* to) {
                message* msg = new_message(PEP_dir_outgoing);
                msg->from = from;
                msg->to = new_identity_list(to);
                msg->shortmsg = strdup("This is a canonical mail from someone to Alice");
                msg->longmsg = strdup("Fa una canzona senza note nere\n"
                                      "Se mai bramasti la mia grazia havere\n"
                                      "Falla d'un tuono ch'invita al dormire,\n"
                                      "Dolcemente, dolcemente facendo la finire.");
                return msg;
            }

            PEP_STATUS add_alternate_key_attachment(PEP_SESSION session,
                                                    message* msg,
                                                    TestUtilsPreset::ident_preset preset_name) {
                const TestUtilsPreset::IdentityInfo& ident_info = TestUtilsPreset::presets[preset_name];
                PEP_STATUS status = TestUtilsPreset::import_preset_key(session, preset_name, false);
                if (status != PEP_STATUS_OK)
                    return status;
                // Shamelessly copied from message_api.c. If you want to do this more often, make
                // the function non-static and expose it through message_api_internal.h.
                // As is, this is a hack to break default key import for testing
                char *keydata = NULL;
                size_t size = 0;
                status = export_key(session, ident_info.fpr, &keydata, &size);
                if (status != PEP_STATUS_OK)
                    return status;

                bloblist_t *bl = bloblist_add(msg->attachments, keydata, size, "application/pgp-keys",
                                              "file://pEpKey.asc");

                if (msg->attachments == NULL && bl)
                    msg->attachments = bl;

                return PEP_STATUS_OK;
            }

            PEP_STATUS gen_testcase_message(TestUtilsPreset::ident_preset preset_name, bool have_key,
                                            bool to_pep, bool trust, int major, int minor, message** outmsg) {
                PEP_STATUS status = PEP_STATUS_OK;
                pEp_identity* me = TestUtilsPreset::generateAndSetPrivateIdentity(session, preset_name);
                pEp_identity* alice = NULL;
                if (!have_key) {
                    alice = TestUtilsPreset::generateOnlyPartnerIdentity(session, TestUtilsPreset::ALICE);
                }
                else if (to_pep) {
                    alice = TestUtilsPreset::generateAndSetpEpPartnerIdentity(session, TestUtilsPreset::ALICE, true, trust);
                }
                else {
                    alice = TestUtilsPreset::generateAndSetOpenPGPPartnerIdentity(session, TestUtilsPreset::ALICE, true, trust);
                }
                if (major > 0) {
                    status = set_protocol_version(session, alice, major, minor);
                }
                *outmsg = gen_outgoing_message_template(me, alice);
                return status;
            }
        private:
            const char* test_suite_name;
            const char* test_name;
            string test_path;
            // Objects declared here can be used by all tests in the GenerateMailsToMessageTypeTest suite.

    };

}  // namespace

// Bob is intended to be a known pEp comm partner to Alice.
// Sylvia is an unknown pEp comm partner to Alice.
// Carol and Julio are known and unknown PGP comm partners, but those have to be generated externally, through, e.g., Thunderbird.
// If you need to do things like write out new mails without attaching keys and stuff, you'll have to do it through the debugger
// and change the structs by hand during runtime.
#if GMTMTT_WRITEOUT

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_unencrypted_bob) {
    string filename = string("test_mails/CanonicalFrom") + PEP_PROTOCOL_VERSION + "BobToAliceUnencrypted.eml";
    message* msg = NULL;
    PEP_STATUS status = gen_testcase_message(TestUtilsPreset::BOB, false,  false, false, -1, -1, &msg);
    ASSERT_OK;
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str());
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_unencrypted_sylvia) {
    string filename = string("test_mails/CanonicalFrom") + PEP_PROTOCOL_VERSION + "SylviaToAliceUnencrypted.eml";
    message* msg = NULL;
    PEP_STATUS status = gen_testcase_message(TestUtilsPreset::SYLVIA, false,  false, false, -1, -1, &msg);
    ASSERT_OK;
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str());
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_OpenPGP_bob) {
    string filename = string("test_mails/CanonicalFrom") + PEP_PROTOCOL_VERSION + "BobToAlice_OpenPGP.eml";
    message* msg = NULL;
    PEP_STATUS status = gen_testcase_message(TestUtilsPreset::BOB, true,  false, false, -1, -1, &msg);
    ASSERT_OK;
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str());
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_OpenPGP_sylvia) {
    string filename = string("test_mails/CanonicalFrom") + PEP_PROTOCOL_VERSION + "SylviaToAlice_OpenPGP.eml";
    message* msg = NULL;
    PEP_STATUS status = gen_testcase_message(TestUtilsPreset::SYLVIA, true,  false, false, -1, -1, &msg);
    ASSERT_OK;
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str());
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_1_0_bob) {
    string filename = string("test_mails/CanonicalFrom") + PEP_PROTOCOL_VERSION + "BobToAlice_1_0.eml";
    message* msg = NULL;
    PEP_STATUS status = gen_testcase_message(TestUtilsPreset::BOB, true,  true, true, 1, 0, &msg);
    ASSERT_OK;
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str());
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_1_0_sylvia) {
    string filename = string("test_mails/CanonicalFrom") + PEP_PROTOCOL_VERSION + "SylviaToAlice_1_0.eml";
    message* msg = NULL;
    PEP_STATUS status = gen_testcase_message(TestUtilsPreset::SYLVIA, true,  true, false, 1, 0, &msg);
    ASSERT_OK;
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str());
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_2_0_bob) {
    string filename = string("test_mails/CanonicalFrom") + PEP_PROTOCOL_VERSION + "BobToAlice_2_0.eml";
    message* msg = NULL;
    PEP_STATUS status = gen_testcase_message(TestUtilsPreset::BOB, true,  true, true, 2, 0, &msg);
    ASSERT_OK;
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str());
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_2_0_sylvia) {
    string filename = string("test_mails/CanonicalFrom") + PEP_PROTOCOL_VERSION + "SylviaToAlice_2_0.eml";
    message* msg = NULL;
    PEP_STATUS status = gen_testcase_message(TestUtilsPreset::SYLVIA, true,  true, true, 2, 0, &msg);
    ASSERT_OK;
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str());
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_2_1_bob) {
    string filename = string("test_mails/CanonicalFrom") + PEP_PROTOCOL_VERSION + "BobToAlice_2_1.eml";
    message* msg = NULL;
    PEP_STATUS status = gen_testcase_message(TestUtilsPreset::BOB, true,  true, true, 2, 1, &msg);
    ASSERT_OK;
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str());
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_2_1_sylvia) {
    string filename = string("test_mails/CanonicalFrom") + PEP_PROTOCOL_VERSION + "SylviaToAlice_2_1.eml";
    message* msg = NULL;
    PEP_STATUS status = gen_testcase_message(TestUtilsPreset::SYLVIA, true,  true, true, 2, 1, &msg);
    ASSERT_OK;
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str());
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_2_2_bob) {
    string filename = string("test_mails/CanonicalFrom") + PEP_PROTOCOL_VERSION + "BobToAlice_2_2.eml";
    message* msg = NULL;
    PEP_STATUS status = gen_testcase_message(TestUtilsPreset::BOB, true,  true, true, 2, 2, &msg);
    ASSERT_OK;
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str());
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_2_2_sylvia) {
    string filename = string("test_mails/CanonicalFrom") + PEP_PROTOCOL_VERSION + "SylviaToAlice_2_2.eml";
    message* msg = NULL;
    PEP_STATUS status = gen_testcase_message(TestUtilsPreset::SYLVIA, true,  true, true, 2, 2, &msg);
    ASSERT_OK;
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str());
    ASSERT_OK;
}

/////// No keys

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_unencrypted_bob_no_attached_key) {
    string filename = string("test_mails/CanonicalFrom") + PEP_PROTOCOL_VERSION + "BobToAliceUnencrypted_NoKey.eml";
    message* msg = NULL;
    PEP_STATUS status = gen_testcase_message(TestUtilsPreset::BOB, false,  false, false, -1, -1, &msg);
    ASSERT_OK;
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str(), PEP_encrypt_flag_force_no_attached_key);
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_unencrypted_sylvia_no_attached_key) {
    string filename = string("test_mails/CanonicalFrom") + PEP_PROTOCOL_VERSION + "SylviaToAliceUnencrypted_NoKey.eml";
    message* msg = NULL;
    PEP_STATUS status = gen_testcase_message(TestUtilsPreset::SYLVIA, false,  false, false, -1, -1, &msg);
    ASSERT_OK;
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str(), PEP_encrypt_flag_force_no_attached_key);
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_OpenPGP_bob_no_attached_key) {
    string filename = string("test_mails/CanonicalFrom") + PEP_PROTOCOL_VERSION + "BobToAlice_OpenPGP_NoKey.eml";
    message* msg = NULL;
    PEP_STATUS status = gen_testcase_message(TestUtilsPreset::BOB, true,  false, false, -1, -1, &msg);
    ASSERT_OK;
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str(), PEP_encrypt_flag_force_no_attached_key);
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_OpenPGP_sylvia_no_attached_key) {
    string filename = string("test_mails/CanonicalFrom") + PEP_PROTOCOL_VERSION + "SylviaToAlice_OpenPGP_NoKey.eml";
    message* msg = NULL;
    PEP_STATUS status = gen_testcase_message(TestUtilsPreset::SYLVIA, true,  false, false, -1, -1, &msg);
    ASSERT_OK;
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str(), PEP_encrypt_flag_force_no_attached_key);
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_1_0_bob_no_attached_key) {
    string filename = string("test_mails/CanonicalFrom") + PEP_PROTOCOL_VERSION + "BobToAlice_1_0_NoKey.eml";
    message* msg = NULL;
    PEP_STATUS status = gen_testcase_message(TestUtilsPreset::BOB, true,  true, true, 1, 0, &msg);
    ASSERT_OK;
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str(), PEP_encrypt_flag_force_no_attached_key);
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_1_0_sylvia_no_attached_key) {
    string filename = string("test_mails/CanonicalFrom") + PEP_PROTOCOL_VERSION + "SylviaToAlice_1_0_NoKey.eml";
    message* msg = NULL;
    PEP_STATUS status = gen_testcase_message(TestUtilsPreset::SYLVIA, true,  true, false, 1, 0, &msg);
    ASSERT_OK;
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str(), PEP_encrypt_flag_force_no_attached_key);
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_2_0_bob_no_attached_key) {
    string filename = string("test_mails/CanonicalFrom") + PEP_PROTOCOL_VERSION + "BobToAlice_2_0_NoKey.eml";
    message* msg = NULL;
    PEP_STATUS status = gen_testcase_message(TestUtilsPreset::BOB, true,  true, true, 2, 0, &msg);
    ASSERT_OK;
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str(), PEP_encrypt_flag_force_no_attached_key);
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_2_0_sylvia_no_attached_key) {
    string filename = string("test_mails/CanonicalFrom") + PEP_PROTOCOL_VERSION + "SylviaToAlice_2_0_NoKey.eml";
    message* msg = NULL;
    PEP_STATUS status = gen_testcase_message(TestUtilsPreset::SYLVIA, true,  true, true, 2, 0, &msg);
    ASSERT_OK;
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str(), PEP_encrypt_flag_force_no_attached_key);
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_2_1_bob_no_attached_key) {
    string filename = string("test_mails/CanonicalFrom") + PEP_PROTOCOL_VERSION + "BobToAlice_2_1_NoKey.eml";
    message* msg = NULL;
    PEP_STATUS status = gen_testcase_message(TestUtilsPreset::BOB, true,  true, true, 2, 1, &msg);
    ASSERT_OK;
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str(), PEP_encrypt_flag_force_no_attached_key);
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_2_1_sylvia_no_attached_key) {
    string filename = string("test_mails/CanonicalFrom") + PEP_PROTOCOL_VERSION + "SylviaToAlice_2_1_NoKey.eml";
    message* msg = NULL;
    PEP_STATUS status = gen_testcase_message(TestUtilsPreset::SYLVIA, true,  true, true, 2, 1, &msg);
    ASSERT_OK;
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str(), PEP_encrypt_flag_force_no_attached_key);
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_2_2_bob_no_attached_key) {
    string filename = string("test_mails/CanonicalFrom") + PEP_PROTOCOL_VERSION + "BobToAlice_2_2_NoKey.eml";
    message* msg = NULL;
    PEP_STATUS status = gen_testcase_message(TestUtilsPreset::BOB, true,  true, true, 2, 2, &msg);
    ASSERT_OK;
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str(), PEP_encrypt_flag_force_no_attached_key);
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_2_2_sylvia_no_attached_key) {
    string filename = string("test_mails/CanonicalFrom") + PEP_PROTOCOL_VERSION + "SylviaToAlice_2_2_NoKey.eml";
    message* msg = NULL;
    PEP_STATUS status = gen_testcase_message(TestUtilsPreset::SYLVIA, true,  true, true, 2, 2, &msg);
    ASSERT_OK;
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str(), PEP_encrypt_flag_force_no_attached_key);
    ASSERT_OK;
}

// Multiple keys
TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_unencrypted_bob_two_keys) {
    string filename = string("test_mails/CanonicalFrom") + PEP_PROTOCOL_VERSION + "BobToAliceUnencrypted_TwoKeys.eml";
    message* msg = NULL;
    PEP_STATUS status = gen_testcase_message(TestUtilsPreset::BOB, false,  false, false, -1, -1, &msg);
    ASSERT_OK;
    status = add_alternate_key_attachment(session, msg, TestUtilsPreset::BOB2);
    ASSERT_OK;
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str());
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_unencrypted_sylvia_two_keys) {
    string filename = string("test_mails/CanonicalFrom") + PEP_PROTOCOL_VERSION + "SylviaToAliceUnencrypted_TwoKeys.eml";
    message* msg = NULL;
    PEP_STATUS status = gen_testcase_message(TestUtilsPreset::SYLVIA, false,  false, false, -1, -1, &msg);
    ASSERT_OK;
    status = add_alternate_key_attachment(session, msg, TestUtilsPreset::SYLVIA2);
    ASSERT_OK;
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str());
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_OpenPGP_bob_two_keys) {
    string filename = string("test_mails/CanonicalFrom") + PEP_PROTOCOL_VERSION + "BobToAlice_OpenPGP_TwoKeys.eml";
    message* msg = NULL;
    PEP_STATUS status = gen_testcase_message(TestUtilsPreset::BOB, true,  false, false, -1, -1, &msg);
    ASSERT_OK;
    status = add_alternate_key_attachment(session, msg, TestUtilsPreset::BOB2);
    ASSERT_OK;
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str());
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_OpenPGP_sylvia_two_keys) {
    string filename = string("test_mails/CanonicalFrom") + PEP_PROTOCOL_VERSION + "SylviaToAlice_OpenPGP_TwoKeys.eml";
    message* msg = NULL;
    PEP_STATUS status = gen_testcase_message(TestUtilsPreset::SYLVIA, true,  false, false, -1, -1, &msg);
    ASSERT_OK;
    status = add_alternate_key_attachment(session, msg, TestUtilsPreset::SYLVIA2);
    ASSERT_OK;
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str());
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_1_0_bob_two_keys) {
    string filename = string("test_mails/CanonicalFrom") + PEP_PROTOCOL_VERSION + "BobToAlice_1_0_TwoKeys.eml";
    message* msg = NULL;
    PEP_STATUS status = gen_testcase_message(TestUtilsPreset::BOB, true,  true, true, 1, 0, &msg);
    ASSERT_OK;
    status = add_alternate_key_attachment(session, msg, TestUtilsPreset::BOB2);
    ASSERT_OK;
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str());
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_1_0_sylvia_two_keys) {
    string filename = string("test_mails/CanonicalFrom") + PEP_PROTOCOL_VERSION + "SylviaToAlice_1_0_TwoKeys.eml";
    message* msg = NULL;
    PEP_STATUS status = gen_testcase_message(TestUtilsPreset::SYLVIA, true,  true, false, 1, 0, &msg);
    ASSERT_OK;
    status = add_alternate_key_attachment(session, msg, TestUtilsPreset::SYLVIA2);
    ASSERT_OK;
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str());
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_2_0_bob_two_keys) {
    string filename = string("test_mails/CanonicalFrom") + PEP_PROTOCOL_VERSION + "BobToAlice_2_0_TwoKeys.eml";
    message* msg = NULL;
    PEP_STATUS status = gen_testcase_message(TestUtilsPreset::BOB, true,  true, true, 2, 0, &msg);
    ASSERT_OK;
    status = add_alternate_key_attachment(session, msg, TestUtilsPreset::BOB2);
    ASSERT_OK;
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str());
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_2_0_sylvia_two_keys) {
    string filename = string("test_mails/CanonicalFrom") + PEP_PROTOCOL_VERSION + "SylviaToAlice_2_0_TwoKeys.eml";
    message* msg = NULL;
    PEP_STATUS status = gen_testcase_message(TestUtilsPreset::SYLVIA, true,  true, true, 2, 0, &msg);
    ASSERT_OK;
    status = add_alternate_key_attachment(session, msg, TestUtilsPreset::SYLVIA2);
    ASSERT_OK;
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str());
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_2_1_bob_two_keys) {
    string filename = string("test_mails/CanonicalFrom") + PEP_PROTOCOL_VERSION + "BobToAlice_2_1_TwoKeys.eml";
    message* msg = NULL;
    PEP_STATUS status = gen_testcase_message(TestUtilsPreset::BOB, true,  true, true, 2, 1, &msg);
    ASSERT_OK;
    status = add_alternate_key_attachment(session, msg, TestUtilsPreset::BOB2);
    ASSERT_OK;
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str());
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_2_1_sylvia_two_keys) {
    string filename = string("test_mails/CanonicalFrom") + PEP_PROTOCOL_VERSION + "SylviaToAlice_2_1_TwoKeys.eml";
    message* msg = NULL;
    PEP_STATUS status = gen_testcase_message(TestUtilsPreset::SYLVIA, true,  true, true, 2, 1, &msg);
    ASSERT_OK;
    status = add_alternate_key_attachment(session, msg, TestUtilsPreset::SYLVIA2);
    ASSERT_OK;
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str());
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_2_2_bob_two_keys) {
    string filename = string("test_mails/CanonicalFrom") + PEP_PROTOCOL_VERSION + "BobToAlice_2_2_TwoKeys.eml";
    message* msg = NULL;
    PEP_STATUS status = gen_testcase_message(TestUtilsPreset::BOB, true,  true, true, 2, 2, &msg);
    ASSERT_OK;
    status = add_alternate_key_attachment(session, msg, TestUtilsPreset::BOB2);
    ASSERT_OK;
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str());
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_2_2_sylvia_two_keys) {
    string filename = string("test_mails/CanonicalFrom") + PEP_PROTOCOL_VERSION + "SylviaToAlice_2_2_TwoKeys.eml";
    message* msg = NULL;
    PEP_STATUS status = gen_testcase_message(TestUtilsPreset::SYLVIA, true,  true, true, 2, 2, &msg);
    ASSERT_OK;
    status = add_alternate_key_attachment(session, msg, TestUtilsPreset::SYLVIA2);
    ASSERT_OK;
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str());
    ASSERT_OK;
}


#endif