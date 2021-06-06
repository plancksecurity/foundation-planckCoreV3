#include <stdlib.h>
#include <string>
#include <cstring>

#include "pEpEngine.h"
#include "pEpEngine_internal.h"
#include "TestUtilities.h"
#include "TestConstants.h"
#include "Engine.h"

#include <gtest/gtest.h>

#define GMTMTT_WRITEOUT 1
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
    string filename = string("test_mails/CanonicalFrom") + PEP_VERSION + "BobToAliceUnencrypted.eml";
    pEp_identity* me = TestUtilsPreset::generateAndSetPrivateIdentity(session, TestUtilsPreset::BOB);
    pEp_identity* alice = TestUtilsPreset::generateOnlyPartnerIdentity(session, TestUtilsPreset::ALICE);
    message* msg = gen_outgoing_message_template(me, alice);
    PEP_STATUS status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str());
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_unencrypted_sylvia) {
    string filename = string("test_mails/CanonicalFrom") + PEP_VERSION + "SylviaToAliceUnencrypted.eml";
    pEp_identity* me = TestUtilsPreset::generateAndSetPrivateIdentity(session, TestUtilsPreset::SYLVIA);
    pEp_identity* alice = TestUtilsPreset::generateOnlyPartnerIdentity(session, TestUtilsPreset::ALICE);
    message* msg = gen_outgoing_message_template(me, alice);
    PEP_STATUS status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str());
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_OpenPGP_bob) {
    string filename = string("test_mails/CanonicalFrom") + PEP_VERSION + "BobToAlice_OpenPGP.eml";
    pEp_identity* me = TestUtilsPreset::generateAndSetPrivateIdentity(session, TestUtilsPreset::BOB);
    pEp_identity* alice = TestUtilsPreset::generateAndSetOpenPGPPartnerIdentity(session, TestUtilsPreset::ALICE, true, false);
    message* msg = gen_outgoing_message_template(me, alice);
    PEP_STATUS status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str());
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_OpenPGP_sylvia) {
    string filename = string("test_mails/CanonicalFrom") + PEP_VERSION + "SylviaToAlice_OpenPGP.eml";
    pEp_identity* me = TestUtilsPreset::generateAndSetPrivateIdentity(session, TestUtilsPreset::SYLVIA);
    pEp_identity* alice = TestUtilsPreset::generateAndSetOpenPGPPartnerIdentity(session, TestUtilsPreset::ALICE, true, false);
    message* msg = gen_outgoing_message_template(me, alice);
    PEP_STATUS status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str());
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_1_0_bob) {
    string filename = string("test_mails/CanonicalFrom") + PEP_VERSION + "BobToAlice_1_0.eml";
    pEp_identity* me = TestUtilsPreset::generateAndSetPrivateIdentity(session, TestUtilsPreset::BOB);
    pEp_identity* alice = TestUtilsPreset::generateAndSetpEpPartnerIdentity(session, TestUtilsPreset::ALICE, true, true);
    int alice_major = 1;
    int alice_minor = 0;
    PEP_STATUS status = set_pEp_version(session, alice, alice_major, alice_minor);
    message* msg = gen_outgoing_message_template(me, alice);
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str());
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_1_0_sylvia) {
    string filename = string("test_mails/CanonicalFrom") + PEP_VERSION + "SylviaToAlice_1_0.eml";
    pEp_identity* me = TestUtilsPreset::generateAndSetPrivateIdentity(session, TestUtilsPreset::SYLVIA);
    pEp_identity* alice = TestUtilsPreset::generateAndSetpEpPartnerIdentity(session, TestUtilsPreset::ALICE, true, false);
    int alice_major = 1;
    int alice_minor = 0;
    PEP_STATUS status = set_pEp_version(session, alice, alice_major, alice_minor);
    message* msg = gen_outgoing_message_template(me, alice);
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str());
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_2_0_bob) {
    string filename = string("test_mails/CanonicalFrom") + PEP_VERSION + "BobToAlice_2_0.eml";
    pEp_identity* me = TestUtilsPreset::generateAndSetPrivateIdentity(session, TestUtilsPreset::BOB);
    pEp_identity* alice = TestUtilsPreset::generateAndSetpEpPartnerIdentity(session, TestUtilsPreset::ALICE, true, true);
    int alice_major = 2;
    int alice_minor = 0;
    PEP_STATUS status = set_pEp_version(session, alice, alice_major, alice_minor);
    ASSERT_OK;
    message* msg = gen_outgoing_message_template(me, alice);
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str());
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_2_0_sylvia) {
    string filename = string("test_mails/CanonicalFrom") + PEP_VERSION + "SylviaToAlice_2_0.eml";
    pEp_identity* me = TestUtilsPreset::generateAndSetPrivateIdentity(session, TestUtilsPreset::SYLVIA);
    pEp_identity* alice = TestUtilsPreset::generateAndSetpEpPartnerIdentity(session, TestUtilsPreset::ALICE, true, true);
    int alice_major = 2;
    int alice_minor = 0;
    PEP_STATUS status = set_pEp_version(session, alice, alice_major, alice_minor);
    ASSERT_OK;
    message* msg = gen_outgoing_message_template(me, alice);
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str());
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_2_1_bob) {
    string filename = string("test_mails/CanonicalFrom") + PEP_VERSION + "BobToAlice_2_1.eml";
    pEp_identity* me = TestUtilsPreset::generateAndSetPrivateIdentity(session, TestUtilsPreset::BOB);
    pEp_identity* alice = TestUtilsPreset::generateAndSetpEpPartnerIdentity(session, TestUtilsPreset::ALICE, true, true);
    int alice_major = 2;
    int alice_minor = 1;
    PEP_STATUS status = set_pEp_version(session, alice, alice_major, alice_minor);
    ASSERT_OK;
    message* msg = gen_outgoing_message_template(me, alice);
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str());
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_2_1_sylvia) {
    string filename = string("test_mails/CanonicalFrom") + PEP_VERSION + "BobToAlice_2_1.eml";
    pEp_identity* me = TestUtilsPreset::generateAndSetPrivateIdentity(session, TestUtilsPreset::SYLVIA);
    pEp_identity* alice = TestUtilsPreset::generateAndSetpEpPartnerIdentity(session, TestUtilsPreset::ALICE, true, true);
    int alice_major = 2;
    int alice_minor = 1;
    PEP_STATUS status = set_pEp_version(session, alice, alice_major, alice_minor);
    ASSERT_OK;
    message* msg = gen_outgoing_message_template(me, alice);
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str());
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_2_2_bob) {
    string filename = string("test_mails/CanonicalFrom") + PEP_VERSION + "BobToAlice_2_2.eml";
    pEp_identity* me = TestUtilsPreset::generateAndSetPrivateIdentity(session, TestUtilsPreset::BOB);
    pEp_identity* alice = TestUtilsPreset::generateAndSetpEpPartnerIdentity(session, TestUtilsPreset::ALICE, true, true);
    int alice_major = 2;
    int alice_minor = 2;
    PEP_STATUS status = set_pEp_version(session, alice, alice_major, alice_minor);
    ASSERT_OK;
    message* msg = gen_outgoing_message_template(me, alice);
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str());
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_2_2_sylvia) {
    string filename = string("test_mails/CanonicalFrom") + PEP_VERSION + "SylviaToAlice_2_2.eml";
    pEp_identity* me = TestUtilsPreset::generateAndSetPrivateIdentity(session, TestUtilsPreset::SYLVIA);
    pEp_identity* alice = TestUtilsPreset::generateAndSetpEpPartnerIdentity(session, TestUtilsPreset::ALICE, true, true);
    int alice_major = 2;
    int alice_minor = 2;
    PEP_STATUS status = set_pEp_version(session, alice, alice_major, alice_minor);
    ASSERT_OK;
    message* msg = gen_outgoing_message_template(me, alice);
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str());
    ASSERT_OK;
}

/////// No keys

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_unencrypted_bob_no_attached_key) {
    string filename = string("test_mails/CanonicalFrom") + PEP_VERSION + "BobToAliceUnencrypted_NoKey.eml";
    pEp_identity* me = TestUtilsPreset::generateAndSetPrivateIdentity(session, TestUtilsPreset::BOB);
    pEp_identity* alice = TestUtilsPreset::generateOnlyPartnerIdentity(session, TestUtilsPreset::ALICE);
    message* msg = gen_outgoing_message_template(me, alice);
    PEP_STATUS status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str(), PEP_encrypt_flag_force_no_attached_key);
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_unencrypted_sylvia_no_attached_key) {
    string filename = string("test_mails/CanonicalFrom") + PEP_VERSION + "SylviaToAliceUnencrypted_NoKey.eml";
    pEp_identity* me = TestUtilsPreset::generateAndSetPrivateIdentity(session, TestUtilsPreset::SYLVIA);
    pEp_identity* alice = TestUtilsPreset::generateOnlyPartnerIdentity(session, TestUtilsPreset::ALICE);
    message* msg = gen_outgoing_message_template(me, alice);
    PEP_STATUS status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str(), PEP_encrypt_flag_force_no_attached_key);
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_OpenPGP_bob_no_attached_key) {
    string filename = string("test_mails/CanonicalFrom") + PEP_VERSION + "BobToAlice_OpenPGP_NoKey.eml";
    pEp_identity* me = TestUtilsPreset::generateAndSetPrivateIdentity(session, TestUtilsPreset::BOB);
    pEp_identity* alice = TestUtilsPreset::generateAndSetOpenPGPPartnerIdentity(session, TestUtilsPreset::ALICE, true, false);
    message* msg = gen_outgoing_message_template(me, alice);
    PEP_STATUS status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str(), PEP_encrypt_flag_force_no_attached_key);
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_OpenPGP_sylvia_no_attached_key) {
    string filename = string("test_mails/CanonicalFrom") + PEP_VERSION + "SylviaToAlice_OpenPGP_NoKey.eml";
    pEp_identity* me = TestUtilsPreset::generateAndSetPrivateIdentity(session, TestUtilsPreset::SYLVIA);
    pEp_identity* alice = TestUtilsPreset::generateAndSetOpenPGPPartnerIdentity(session, TestUtilsPreset::ALICE, true, false);
    message* msg = gen_outgoing_message_template(me, alice);
    PEP_STATUS status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str(), PEP_encrypt_flag_force_no_attached_key);
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_1_0_bob_no_attached_key) {
    string filename = string("test_mails/CanonicalFrom") + PEP_VERSION + "BobToAlice_1_0_NoKey.eml";
    pEp_identity* me = TestUtilsPreset::generateAndSetPrivateIdentity(session, TestUtilsPreset::BOB);
    pEp_identity* alice = TestUtilsPreset::generateAndSetpEpPartnerIdentity(session, TestUtilsPreset::ALICE, true, true);
    int alice_major = 1;
    int alice_minor = 0;
    PEP_STATUS status = set_pEp_version(session, alice, alice_major, alice_minor);
    message* msg = gen_outgoing_message_template(me, alice);
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str(), PEP_encrypt_flag_force_no_attached_key);
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_1_0_sylvia_no_attached_key) {
    string filename = string("test_mails/CanonicalFrom") + PEP_VERSION + "SylviaToAlice_1_0_NoKey.eml";
    pEp_identity* me = TestUtilsPreset::generateAndSetPrivateIdentity(session, TestUtilsPreset::SYLVIA);
    pEp_identity* alice = TestUtilsPreset::generateAndSetpEpPartnerIdentity(session, TestUtilsPreset::ALICE, true, false);
    int alice_major = 1;
    int alice_minor = 0;
    PEP_STATUS status = set_pEp_version(session, alice, alice_major, alice_minor);
    message* msg = gen_outgoing_message_template(me, alice);
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str(), PEP_encrypt_flag_force_no_attached_key);
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_2_0_bob_no_attached_key) {
    string filename = string("test_mails/CanonicalFrom") + PEP_VERSION + "BobToAlice_2_0_NoKey.eml";
    pEp_identity* me = TestUtilsPreset::generateAndSetPrivateIdentity(session, TestUtilsPreset::BOB);
    pEp_identity* alice = TestUtilsPreset::generateAndSetpEpPartnerIdentity(session, TestUtilsPreset::ALICE, true, true);
    int alice_major = 2;
    int alice_minor = 0;
    PEP_STATUS status = set_pEp_version(session, alice, alice_major, alice_minor);
    ASSERT_OK;
    message* msg = gen_outgoing_message_template(me, alice);
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str(), PEP_encrypt_flag_force_no_attached_key);
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_2_0_sylvia_no_attached_key) {
    string filename = string("test_mails/CanonicalFrom") + PEP_VERSION + "SylviaToAlice_2_0_NoKey.eml";
    pEp_identity* me = TestUtilsPreset::generateAndSetPrivateIdentity(session, TestUtilsPreset::SYLVIA);
    pEp_identity* alice = TestUtilsPreset::generateAndSetpEpPartnerIdentity(session, TestUtilsPreset::ALICE, true, true);
    int alice_major = 2;
    int alice_minor = 0;
    PEP_STATUS status = set_pEp_version(session, alice, alice_major, alice_minor);
    ASSERT_OK;
    message* msg = gen_outgoing_message_template(me, alice);
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str(), PEP_encrypt_flag_force_no_attached_key);
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_2_1_bob_no_attached_key) {
    string filename = string("test_mails/CanonicalFrom") + PEP_VERSION + "BobToAlice_2_1_NoKey.eml";
    pEp_identity* me = TestUtilsPreset::generateAndSetPrivateIdentity(session, TestUtilsPreset::BOB);
    pEp_identity* alice = TestUtilsPreset::generateAndSetpEpPartnerIdentity(session, TestUtilsPreset::ALICE, true, true);
    int alice_major = 2;
    int alice_minor = 1;
    PEP_STATUS status = set_pEp_version(session, alice, alice_major, alice_minor);
    ASSERT_OK;
    message* msg = gen_outgoing_message_template(me, alice);
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str(), PEP_encrypt_flag_force_no_attached_key);
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_2_1_sylvia_no_attached_key) {
    string filename = string("test_mails/CanonicalFrom") + PEP_VERSION + "SylviaToAlice_2_1_NoKey.eml";
    pEp_identity* me = TestUtilsPreset::generateAndSetPrivateIdentity(session, TestUtilsPreset::SYLVIA);
    pEp_identity* alice = TestUtilsPreset::generateAndSetpEpPartnerIdentity(session, TestUtilsPreset::ALICE, true, true);
    int alice_major = 2;
    int alice_minor = 1;
    PEP_STATUS status = set_pEp_version(session, alice, alice_major, alice_minor);
    ASSERT_OK;
    message* msg = gen_outgoing_message_template(me, alice);
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str(), PEP_encrypt_flag_force_no_attached_key);
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_2_2_bob_no_attached_key) {
    string filename = string("test_mails/CanonicalFrom") + PEP_VERSION + "BobToAlice_2_2_NoKey.eml";
    pEp_identity* me = TestUtilsPreset::generateAndSetPrivateIdentity(session, TestUtilsPreset::BOB);
    pEp_identity* alice = TestUtilsPreset::generateAndSetpEpPartnerIdentity(session, TestUtilsPreset::ALICE, true, true);
    int alice_major = 2;
    int alice_minor = 2;
    PEP_STATUS status = set_pEp_version(session, alice, alice_major, alice_minor);
    ASSERT_OK;
    message* msg = gen_outgoing_message_template(me, alice);
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str(), PEP_encrypt_flag_force_no_attached_key);
    ASSERT_OK;
}

TEST_F(GenerateMailsToMessageTypeTest, check_generate_mails_to_message_type_2_2_sylvia_no_attached_key) {
    string filename = string("test_mails/CanonicalFrom") + PEP_VERSION + "SylviaToAlice_2_2_NoKey.eml";
    pEp_identity* me = TestUtilsPreset::generateAndSetPrivateIdentity(session, TestUtilsPreset::SYLVIA);
    pEp_identity* alice = TestUtilsPreset::generateAndSetpEpPartnerIdentity(session, TestUtilsPreset::ALICE, true, true);
    int alice_major = 2;
    int alice_minor = 2;
    PEP_STATUS status = set_pEp_version(session, alice, alice_major, alice_minor);
    ASSERT_OK;
    message* msg = gen_outgoing_message_template(me, alice);
    status = vanilla_encrypt_and_write_to_file(session, msg, filename.c_str(), PEP_encrypt_flag_force_no_attached_key);
    ASSERT_OK;
}
#endif