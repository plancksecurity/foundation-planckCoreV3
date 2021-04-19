// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "TestConstants.h"
#include <stdlib.h>
#include <string>
#include <iostream>
#include <fstream>
#include <cstring> // for strcmp()

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "keymanagement.h"
#include "message_api.h"
#include "mime.h"
#include "test_util.h" // for slurp()



#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for PepSubjectReceivedTest
    class PepSubjectReceivedTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            PepSubjectReceivedTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~PepSubjectReceivedTest() override {
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

        private:
            const char* test_suite_name;
            const char* test_name;
            string test_path;
            // Objects declared here can be used by all tests in the PepSubjectReceivedTest suite.

    };

}  // namespace


TEST_F(PepSubjectReceivedTest, check_pep_subject_received) {

    const char* keytexts[3];
    const char* alice_fpr = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";
 
    const string keytextkey1 = slurp("test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    const string keytextkey2 = slurp("test_keys/priv/pep-test-recip-0x08DB0AEE_priv.asc");
    const string keytextkey3 = slurp("test_keys/pub/pep-test-recip-0x08DB0AEE_pub.asc");
    PEP_STATUS statuskey1 = import_key(session, keytextkey1.c_str(), keytextkey1.length(), NULL);
    PEP_STATUS statuskey2 = import_key(session, keytextkey2.c_str(), keytextkey2.length(), NULL);
    PEP_STATUS statuskey3 = import_key(session, keytextkey3.c_str(), keytextkey3.length(), NULL);

    pEp_identity * me = new_identity("pep.test.recip@kgrothoff.org", "93D19F24AD6F4C4BA9134AAF84D9217908DB0AEE", PEP_OWN_USERID, "pEp Test Recipient");
    me->me = true;
    PEP_STATUS status = myself(session, me);

    pEp_identity * you = new_identity("pep.test.alice@pep-project.org", NULL, "TOFU_pep.test.alice@pep-project.org", "Alice Test");
    you->me = false;
    status = set_fpr_preserve_ident(session, you, alice_fpr, false);
    ASSERT_OK;

    status = update_identity(session, you);
    ASSERT_OK;  
    status = trust_personal_key(session, you);
    ASSERT_OK;
    status = update_identity(session, you);
    ASSERT_OK;
    ASSERT_STREQ(you->fpr, alice_fpr);
    ASSERT_EQ(you->comm_type, PEP_ct_OpenPGP);
        
    output_stream << "------------------------------------------------------------------------------------------" << endl;
    output_stream << "Test 1a: Normal encrypted mail, pEp as substitute subject, regular subject in crypto text." << endl;
    output_stream << "------------------------------------------------------------------------------------------" << endl;

    string mailtext = slurp("test_mails/pEp_subject_normal_1a.eml");

    message* msg_ptr = nullptr;
    message* dest_msg = nullptr;
    message* final_ptr = nullptr;
    stringlist_t* keylist = nullptr;
    PEP_rating rating;
    PEP_decrypt_flags_t flags;

    status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr, NULL);
    ASSERT_OK;
    ASSERT_NOTNULL(msg_ptr);
    final_ptr = msg_ptr;
    //flags = PEP_decrypt_deliver_pgpmime_badsigned; // We created this test before deciding not to display unsigned messages
    flags = 0;
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
    final_ptr = dest_msg ? dest_msg : msg_ptr;

    output_stream << "shortmsg: " << final_ptr->shortmsg << endl << endl;
    output_stream << "longmsg: " << final_ptr->longmsg << endl << endl;
    output_stream << "longmsg_formatted: " << (final_ptr->longmsg_formatted ? final_ptr->longmsg_formatted : "(empty)") << endl << endl;

    ASSERT_STREQ("This is the usual pEp subject that should replace the above.", final_ptr->shortmsg);

    output_stream << "Test 1a: Subject replaced as expected." << endl << endl;

    if (final_ptr == dest_msg)
    	free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);

    output_stream << "------------------------------------------------------------------------------------------" << endl;
    output_stream << "Test 1b: Normal encrypted mail, p≡p as substitute subject, regular subject in crypto text." << endl;
    output_stream << "------------------------------------------------------------------------------------------" << endl;

    mailtext = slurp("test_mails/p3p_subject_normal_1b.eml");

    msg_ptr = nullptr;
    dest_msg = nullptr;
    final_ptr = nullptr;
    keylist = nullptr;
    rating = PEP_rating_unreliable;

    status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr, NULL);
    ASSERT_OK;
    ASSERT_NOTNULL(msg_ptr);
    final_ptr = msg_ptr;
    //flags = PEP_decrypt_deliver_pgpmime_badsigned; // We created this test before deciding not to display unsigned messages
    flags = 0;
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
    final_ptr = dest_msg ? dest_msg : msg_ptr;

    output_stream << "shortmsg: " << final_ptr->shortmsg << endl << endl;
    output_stream << "longmsg: " << final_ptr->longmsg << endl << endl;
    output_stream << "longmsg_formatted: " << (final_ptr->longmsg_formatted ? final_ptr->longmsg_formatted : "(empty)") << endl << endl;

    ASSERT_STREQ("This is the usual pEp subject that should replace the above.", final_ptr->shortmsg);

    output_stream << "Test 1b: Subject replaced as expected." << endl << endl;

    if (final_ptr == dest_msg)
    	free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);

    output_stream << "-------------------------------------------------------------------------------------------------" << endl;
    output_stream << "Test 2a: Normal encrypted/signed mail, pEp as substitute subject, regular subject in crypto text." << endl;
    output_stream << "-------------------------------------------------------------------------------------------------" << endl;

    msg_ptr = nullptr;
    dest_msg = nullptr;
    final_ptr = nullptr;
    keylist = nullptr;
    rating = PEP_rating_unreliable;

    mailtext = slurp("test_mails/pEp_subject_normal_signed_2a.eml");

    status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr, NULL);
    ASSERT_OK;
    ASSERT_NOTNULL(msg_ptr);
    final_ptr = msg_ptr;
    flags = 0;
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
    final_ptr = dest_msg ? dest_msg : msg_ptr;

    output_stream << "shortmsg: " << final_ptr->shortmsg << endl << endl;
    output_stream << "longmsg: " << final_ptr->longmsg << endl << endl;
    output_stream << "longmsg_formatted: " << (final_ptr->longmsg_formatted ? final_ptr->longmsg_formatted : "(empty)") << endl << endl;

    ASSERT_STREQ("Now signed!", final_ptr->shortmsg);

    output_stream << "Test 2a: Subject replaced as expected." << endl << endl;

    if (final_ptr == dest_msg)
        free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);

    output_stream << "-------------------------------------------------------------------------------------------------" << endl;
    output_stream << "Test 2b: Normal encrypted/signed mail, p≡p as substitute subject, regular subject in crypto text." << endl;
    output_stream << "-------------------------------------------------------------------------------------------------" << endl;

    msg_ptr = nullptr;
    dest_msg = nullptr;
    final_ptr = nullptr;
    keylist = nullptr;
    rating = PEP_rating_unreliable;

    mailtext = slurp("test_mails/p3p_subject_normal_signed_2b.eml");

    status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr, NULL);
    ASSERT_OK;
    ASSERT_NOTNULL(msg_ptr);
    final_ptr = msg_ptr;
    flags = 0;
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
    final_ptr = dest_msg ? dest_msg : msg_ptr;

    output_stream << "shortmsg: " << final_ptr->shortmsg << endl << endl;
    output_stream << "longmsg: " << final_ptr->longmsg << endl << endl;
    output_stream << "longmsg_formatted: " << (final_ptr->longmsg_formatted ? final_ptr->longmsg_formatted : "(empty)") << endl << endl;

    ASSERT_STREQ("Now signed!", final_ptr->shortmsg);

    output_stream << "Test 2b: Subject replaced as expected." << endl << endl;

    if (final_ptr == dest_msg)
        free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);


    output_stream << "---------------------------------------------------------------------------" << endl;
    output_stream << "Test 3a: Encrypted mail, pEp as displayed subject, no subject in body text." << endl;
    output_stream << "---------------------------------------------------------------------------" << endl;

    msg_ptr = nullptr;
    dest_msg = nullptr;
    final_ptr = nullptr;
    keylist = nullptr;
    rating = PEP_rating_unreliable;

    mailtext = slurp("test_mails/pEp_encrypted_subject_IS_pEp_3a.eml");

    status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr, NULL);
    ASSERT_OK;
    ASSERT_NOTNULL(msg_ptr);
    final_ptr = msg_ptr;
    //flags = PEP_decrypt_deliver_pgpmime_badsigned; // We created this test before deciding not to display unsigned messages
    flags = 0;
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
    final_ptr = dest_msg ? dest_msg : msg_ptr;

    output_stream << "shortmsg: " << final_ptr->shortmsg << endl << endl;
    output_stream << "longmsg: " << final_ptr->longmsg << endl << endl;
    output_stream << "longmsg_formatted: " << (final_ptr->longmsg_formatted ? final_ptr->longmsg_formatted : "(empty)") << endl << endl;

    ASSERT_STREQ("pEp", final_ptr->shortmsg);

    output_stream << "Test 3a: Subject remains intact as desired." << endl << endl;

    if (final_ptr == dest_msg)
        free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);

    output_stream << "---------------------------------------------------------------------------" << endl;
    output_stream << "Test 3b: Encrypted mail, p≡p as displayed subject, no subject in body text." << endl;
    output_stream << "---------------------------------------------------------------------------" << endl;

    msg_ptr = nullptr;
    dest_msg = nullptr;
    final_ptr = nullptr;
    keylist = nullptr;
    rating = PEP_rating_unreliable;

    mailtext = slurp("test_mails/p3p_encrypted_subject_IS_pEp_3b.eml");

    status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr, NULL);
    ASSERT_OK;
    ASSERT_NOTNULL(msg_ptr);
    final_ptr = msg_ptr;
    //flags = PEP_decrypt_deliver_pgpmime_badsigned; // We created this test before deciding not to display unsigned messages
    flags = 0;
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
    final_ptr = dest_msg ? dest_msg : msg_ptr;

    output_stream << "shortmsg: " << final_ptr->shortmsg << endl << endl;
    output_stream << "longmsg: " << final_ptr->longmsg << endl << endl;
    output_stream << "longmsg_formatted: " << (final_ptr->longmsg_formatted ? final_ptr->longmsg_formatted : "(empty)") << endl << endl;

    ASSERT_STREQ("pEp", final_ptr->shortmsg);

    output_stream << "Test 3: Subject remains intact as desired." << endl << endl;

    if (final_ptr == dest_msg)
        free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);


    output_stream << "----------------------------------------------------------------------------" << endl;
    output_stream << "Test 4a: Encrypted mail, pEp as displayed subject, pEp subject in body text." << endl;
    output_stream << "----------------------------------------------------------------------------" << endl;

    msg_ptr = nullptr;
    dest_msg = nullptr;
    final_ptr = nullptr;
    keylist = nullptr;
    rating = PEP_rating_unreliable;

    mailtext = slurp("test_mails/pEp_subject_pEp_replaced_w_pEp_4a.eml");

    status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr, NULL);
    ASSERT_OK;
    ASSERT_NOTNULL(msg_ptr);
    final_ptr = msg_ptr;
    //flags = PEP_decrypt_deliver_pgpmime_badsigned; // We created this test before deciding not to display unsigned messages
    flags = 0;
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
    final_ptr = dest_msg ? dest_msg : msg_ptr;

    output_stream << "shortmsg: " << final_ptr->shortmsg << endl << endl;
    output_stream << "longmsg: " << final_ptr->longmsg << endl << endl;
    output_stream << "longmsg_formatted: " << (final_ptr->longmsg_formatted ? final_ptr->longmsg_formatted : "(empty)") << endl << endl;

    ASSERT_STREQ("pEp", final_ptr->shortmsg);

    output_stream << "Test 4a: Subject correct." << endl << endl;

    if (final_ptr == dest_msg)
        free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);

    output_stream << "----------------------------------------------------------------------------" << endl;
    output_stream << "Test 4b: Encrypted mail, p≡p as displayed subject, pEp subject in body text." << endl;
    output_stream << "----------------------------------------------------------------------------" << endl;

    msg_ptr = nullptr;
    dest_msg = nullptr;
    final_ptr = nullptr;
    keylist = nullptr;
    rating = PEP_rating_unreliable;

    mailtext = slurp("test_mails/pEp_subject_pEp_replaced_w_p3p_4b.eml");

    status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr, NULL);
    ASSERT_OK;
    ASSERT_NOTNULL(msg_ptr);
    final_ptr = msg_ptr;
    //flags = PEP_decrypt_deliver_pgpmime_badsigned; // We created this test before deciding not to display unsigned messages
    flags = 0;
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
    final_ptr = dest_msg ? dest_msg : msg_ptr;

    output_stream << "shortmsg: " << final_ptr->shortmsg << endl << endl;
    output_stream << "longmsg: " << final_ptr->longmsg << endl << endl;
    output_stream << "longmsg_formatted: " << (final_ptr->longmsg_formatted ? final_ptr->longmsg_formatted : "(empty)") << endl << endl;

    ASSERT_STREQ("pEp", final_ptr->shortmsg);

    output_stream << "Test 4b: Subject correct." << endl << endl;

    if (final_ptr == dest_msg)
        free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);

    output_stream << "----------------------------------------------------------------------------" << endl;
    output_stream << "Test 4c: Encrypted mail, pEp as displayed subject, p≡p subject in body text." << endl;
    output_stream << "----------------------------------------------------------------------------" << endl;

    msg_ptr = nullptr;
    dest_msg = nullptr;
    final_ptr = nullptr;
    keylist = nullptr;
    rating = PEP_rating_unreliable;

    mailtext = slurp("test_mails/pEp_subject_p3p_replaced_w_pEp_4c.eml");

    status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr, NULL);
    ASSERT_OK;
    ASSERT_NOTNULL(msg_ptr);
    final_ptr = msg_ptr;
    //flags = PEP_decrypt_deliver_pgpmime_badsigned; // We created this test before deciding not to display unsigned messages
    flags = 0;
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
    final_ptr = dest_msg ? dest_msg : msg_ptr;

    output_stream << "shortmsg: " << final_ptr->shortmsg << endl << endl;
    output_stream << "longmsg: " << final_ptr->longmsg << endl << endl;
    output_stream << "longmsg_formatted: " << (final_ptr->longmsg_formatted ? final_ptr->longmsg_formatted : "(empty)") << endl << endl;

    ASSERT_STREQ("p≡p", final_ptr->shortmsg);

    output_stream << "Test 4c: Subject correct." << endl << endl;

    if (final_ptr == dest_msg)
        free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);

    output_stream << "----------------------------------------------------------------------------" << endl;
    output_stream << "Test 4d: Encrypted mail, p≡p as displayed subject, p≡p subject in body text." << endl;
    output_stream << "----------------------------------------------------------------------------" << endl;

    msg_ptr = nullptr;
    dest_msg = nullptr;
    final_ptr = nullptr;
    keylist = nullptr;
    rating = PEP_rating_unreliable;

    mailtext = slurp("test_mails/pEp_subject_p3p_replaced_w_p3p_4d.eml");

    status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr, NULL);
    ASSERT_OK;
    ASSERT_NOTNULL(msg_ptr);
    final_ptr = msg_ptr;
    //flags = PEP_decrypt_deliver_pgpmime_badsigned; // We created this test before deciding not to display unsigned messages
    flags = 0;
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
    final_ptr = dest_msg ? dest_msg : msg_ptr;

    output_stream << "shortmsg: " << final_ptr->shortmsg << endl << endl;
    output_stream << "longmsg: " << final_ptr->longmsg << endl << endl;
    output_stream << "longmsg_formatted: " << (final_ptr->longmsg_formatted ? final_ptr->longmsg_formatted : "(empty)") << endl << endl;

    ASSERT_STREQ("p≡p", final_ptr->shortmsg);

    output_stream << "Test 4d: Subject correct, in any event." << endl << endl;

    if (final_ptr == dest_msg)
        free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);


    output_stream << "-------------------------------------------------------------------------" << endl;
    output_stream << "Test 5a: Unencrypted variant where pEp in the subject line is the subject." << endl;
    output_stream << "-------------------------------------------------------------------------" << endl;

    msg_ptr = nullptr;
    dest_msg = nullptr;
    final_ptr = nullptr;
    keylist = nullptr;
    rating = PEP_rating_unreliable;

    mailtext = slurp("test_mails/pEp_unencrypted_pEp_subject_5a.eml");

    status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr, NULL);
    ASSERT_OK;
    ASSERT_NOTNULL(msg_ptr);
    final_ptr = msg_ptr;
    //flags = PEP_decrypt_deliver_pgpmime_badsigned; // We created this test before deciding not to display unsigned messages
    flags = 0;
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
    final_ptr = dest_msg ? dest_msg : msg_ptr;

    output_stream << "shortmsg: " << final_ptr->shortmsg << endl << endl;
    output_stream << "longmsg: " << final_ptr->longmsg << endl << endl;
    output_stream << "longmsg_formatted: " << (final_ptr->longmsg_formatted ? final_ptr->longmsg_formatted : "(empty)") << endl << endl;

    ASSERT_STREQ("pEp", final_ptr->shortmsg);

    output_stream << "Test 5a: Subject remains intact." << endl << endl;

    if (final_ptr == dest_msg)
        free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);


    output_stream << "--------------------------------------------------------------------------" << endl;
    output_stream << "Test 5b: Unencrypted variant where p≡p in the subject line is the subject." << endl;
    output_stream << "--------------------------------------------------------------------------" << endl;

    msg_ptr = nullptr;
    dest_msg = nullptr;
    final_ptr = nullptr;
    keylist = nullptr;
    rating = PEP_rating_unreliable;

    mailtext = slurp("test_mails/pEp_unencrypted_p3p_subject_5b.eml");

    status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr, NULL);
    ASSERT_OK;
    ASSERT_NOTNULL(msg_ptr);
    final_ptr = msg_ptr;
    //flags = PEP_decrypt_deliver_pgpmime_badsigned; // We created this test before deciding not to display unsigned messages
    flags = 0;
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
    final_ptr = dest_msg ? dest_msg : msg_ptr;

    output_stream << "shortmsg: " << final_ptr->shortmsg << endl << endl;
    output_stream << "longmsg: " << final_ptr->longmsg << endl << endl;
    output_stream << "longmsg_formatted: " << (final_ptr->longmsg_formatted ? final_ptr->longmsg_formatted : "(empty)") << endl << endl;

    ASSERT_STREQ("p≡p", final_ptr->shortmsg);

    output_stream << "Test 5b: Subject remains intact." << endl << endl;

    if (final_ptr == dest_msg)
        free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);

    output_stream << "----------------------------------------------------------------------------------------------------------------------" << endl;
    output_stream << "Test 6: Normal unencrypted email where a subject line exists in the text but the subject is not a replacement subject." << endl;
    output_stream << "----------------------------------------------------------------------------------------------------------------------" << endl;

    msg_ptr = nullptr;
    dest_msg = nullptr;
    final_ptr = nullptr;
    keylist = nullptr;
    rating = PEP_rating_unreliable;

    mailtext = slurp("test_mails/pEp_subject_normal_unencrypted_6.eml");

    status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr, NULL);
    ASSERT_OK;
    ASSERT_NOTNULL(msg_ptr);
    final_ptr = msg_ptr;
    //flags = PEP_decrypt_deliver_pgpmime_badsigned; // We created this test before deciding not to display unsigned messages
    flags = 0;
    status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
    final_ptr = dest_msg ? dest_msg : msg_ptr;

    output_stream << "shortmsg: " << final_ptr->shortmsg << endl << endl;
    output_stream << "longmsg: " << final_ptr->longmsg << endl << endl;
    output_stream << "longmsg_formatted: " << (final_ptr->longmsg_formatted ? final_ptr->longmsg_formatted : "(empty)") << endl << endl;

    ASSERT_STREQ("This is just a normal subject, really", final_ptr->shortmsg);

    output_stream << "Test 6: Subject remains intact." << endl << endl;

    if (final_ptr == dest_msg)
        free_message(dest_msg);
    free_message(msg_ptr);
    free_stringlist(keylist);
}
