// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <cstring>
#include <string>

#include <cpptest.h>
#include "test_util.h"

#include "pEpEngine.h"
#include "mime.h"

#include "EngineTestIndividualSuite.h"
#include "SenderFPRTests.h"

using namespace std;

SenderFPRTests::SenderFPRTests(string suitename, string test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("SenderFPRTests::check_sender_f_p_r"),
                                                                      static_cast<Func>(&SenderFPRTests::check_sender_f_p_r)));
}

void SenderFPRTests::check_sender_f_p_r() {
    const char* alice_fpr = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";
    const char* bob_fpr = "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39";
    PEP_STATUS status = read_file_and_import_key(session,
                "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    TEST_ASSERT(status == PEP_KEY_IMPORTED);
    status = set_up_ident_from_scratch(session,
                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                "pep.test.alice@pep-project.org", alice_fpr,
                PEP_OWN_USERID, "Alice in Wonderland", NULL, true
            );
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT_MSG(slurp_and_import_key(session, "test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc"),
                    "Unable to import test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc");
                    

    message* msg = new_message(PEP_dir_outgoing);
    pEp_identity* alice = new_identity("pep.test.alice@pep-project.org", NULL, PEP_OWN_USERID, NULL);                
    pEp_identity* bob = new_identity("pep.test.bob@pep-project.org", NULL, "Bob", NULL);
    status = myself(session, alice);
    TEST_ASSERT(status == PEP_STATUS_OK);
    status = update_identity(session, bob);
    TEST_ASSERT(status == PEP_STATUS_OK);
    
    status = set_as_pEp_user(session, bob);
    TEST_ASSERT(status == PEP_STATUS_OK);

    msg->to = new_identity_list(bob);
    msg->from = alice;
    msg->shortmsg = strdup("Yo Bob!");
    msg->longmsg = strdup("Look at my hot new sender fpr field!");

    message* enc_msg = NULL;
    
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(stringpair_list_find(enc_msg->opt_fields, "X-pEp-Sender-FPR") == NULL);
    
    message* dec_msg = NULL;

    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    TEST_ASSERT(status == PEP_STATUS_OK);

    char* text = NULL;
    mime_encode_message(dec_msg, false, &text);
    cout << text << endl;
    free(text);
    
    stringpair_list_t* fpr_node = stringpair_list_find(dec_msg->opt_fields, "X-pEp-Sender-FPR");
    TEST_ASSERT(fpr_node);
    TEST_ASSERT(strcmp(fpr_node->value->value, alice_fpr) == 0);
}
