// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <cstring>
#include <string>

#include <cpptest.h>
#include "test_util.h"

#include "pEpEngine.h"

#include "EngineTestIndividualSuite.h"
#include "Message2_1Tests.h"

using namespace std;

Message2_1Tests::Message2_1Tests(string suitename, string test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("Message2_1Tests::check_message2_1_recip_2_0"),
                                                                      static_cast<Func>(&Message2_1Tests::check_message2_1_recip_2_0)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("Message2_1Tests::check_message2_1_recip_OpenPGP"),
                                                                      static_cast<Func>(&Message2_1Tests::check_message2_1_recip_OpenPGP)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("Message2_1Tests::check_message2_1_recip_2_1"),
                                                                      static_cast<Func>(&Message2_1Tests::check_message2_1_recip_2_1)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("Message2_1Tests::check_message2_1_recip_1_0_from_msg_OpenPGP"),
                                                                      static_cast<Func>(&Message2_1Tests::check_message2_1_recip_1_0_from_msg_OpenPGP)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("Message2_1Tests::check_message2_1_recip_2_0_from_msg"),
                                                                      static_cast<Func>(&Message2_1Tests::check_message2_1_recip_2_0_from_msg)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("Message2_1Tests::check_message2_1_recip_2_1_from_msg"),
                                                                      static_cast<Func>(&Message2_1Tests::check_message2_1_recip_2_1_from_msg)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("Message2_1Tests::check_message2_1_recip_mixed_2_0"),
                                                                      static_cast<Func>(&Message2_1Tests::check_message2_1_recip_mixed_2_0)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("Message2_1Tests::check_message2_1_recip_mixed_1_0_OpenPGP"),
                                                                      static_cast<Func>(&Message2_1Tests::check_message2_1_recip_mixed_1_0_OpenPGP)));
}

bool Message2_1Tests::verify_message_version_produced(message* enc_msg, unsigned int* maj_inout, unsigned int* min_inout) {
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

    cout << ptext << endl;

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

void Message2_1Tests::check_message2_1_recip_2_0() {

    pEp_identity* alice = NULL;
    pEp_identity* carol = NULL;
    
    PEP_STATUS status = set_up_preset(session, ALICE, 
                                      true, true, true, true, true, &alice);

    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(alice);
    
    status = set_up_preset(session, CAROL, 
                           false, true, false, false, false, &carol);

    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(carol);

    // default should be 2.0 after setting pep status
    status = update_identity(session, carol);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(carol->major_ver == 2);
    TEST_ASSERT(carol->minor_ver == 0);
    // generate message
    pEp_identity* carol_to = new_identity(carol->address, NULL, NULL, NULL);
    
    message* msg = new_message(PEP_dir_outgoing);
    
    msg->from = alice;
    msg->to = new_identity_list(carol_to);
    msg->shortmsg = strdup("Boom shaka laka");
    msg->longmsg = strdup("Don't you get sick of these?");
    
    message* enc_msg = NULL;

    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    TEST_ASSERT(status == PEP_STATUS_OK);
    
    // ensure sent message is in 2.0 format
    unsigned int major = 2;
    unsigned int minor = 0;
    TEST_ASSERT_MSG(verify_message_version_produced(enc_msg, &major, &minor),
                                                    (to_string(major) + "." + to_string(minor)).c_str());
    
    free_identity(carol);
    free_message(msg);
    free_message(enc_msg);
    TEST_ASSERT(true);
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

void Message2_1Tests::check_message2_1_recip_OpenPGP() {
    // set recip to 1.0
    pEp_identity* alice = NULL;
    pEp_identity* carol = NULL;
    
    PEP_STATUS status = set_up_preset(session, ALICE, 
                                      true, true, true, true, true, &alice);

    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(alice);
    
    status = set_up_preset(session, CAROL, 
                           false, false, false, false, false, &carol);

    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(carol);

    status = update_identity(session, carol);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(carol->major_ver < 2);
    TEST_ASSERT(carol->minor_ver == 0);

    // generate message
    pEp_identity* carol_to = new_identity(carol->address, NULL, NULL, NULL);
    
    message* msg = new_message(PEP_dir_outgoing);
    
    msg->from = alice;
    msg->to = new_identity_list(carol_to);
    msg->shortmsg = strdup("Boom shaka laka");
    msg->longmsg = strdup("Don't you get sick of these?");
    
    message* enc_msg = NULL;

    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    TEST_ASSERT(status == PEP_STATUS_OK);
    
    // ensure sent message is in 1.0 format
    unsigned int major = 1;
    unsigned int minor = 0;
    TEST_ASSERT_MSG(verify_message_version_produced(enc_msg, &major, &minor),
                                                    (to_string(major) + "." + to_string(minor)).c_str());
    
    free_identity(carol);
    free_message(msg);
    free_message(enc_msg);
    TEST_ASSERT(true);
    
    // generate message
    
    // ensure sent message is in 1.0 format
    
    TEST_ASSERT(true);
}

void Message2_1Tests::check_message2_1_recip_2_1() {
    // set recip to 2.1
    
    pEp_identity* alice = NULL;
    pEp_identity* carol = NULL;
    
    PEP_STATUS status = set_up_preset(session, ALICE, 
                                      true, true, true, true, true, &alice);

    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(alice);
    
    status = set_up_preset(session, CAROL, 
                           true, true, false, false, false, &carol);

    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(carol);

    status = set_pEp_version(session, carol, 2, 1);
    
    // default should be 2.1 after setting pep status
    status = update_identity(session, carol);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(carol->major_ver == 2);
    TEST_ASSERT(carol->minor_ver == 1);
    // generate message
    pEp_identity* carol_to = new_identity(carol->address, NULL, NULL, NULL);
    
    message* msg = new_message(PEP_dir_outgoing);
    
    msg->from = alice;
    msg->to = new_identity_list(carol_to);
    msg->shortmsg = strdup("Boom shaka laka");
    msg->longmsg = strdup("Don't you get sick of these?");
    
    message* enc_msg = NULL;

    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    TEST_ASSERT(status == PEP_STATUS_OK);
    
    // ensure sent message is in 2.0 format
    unsigned int major = 2;
    unsigned int minor = 1;
    TEST_ASSERT_MSG(verify_message_version_produced(enc_msg, &major, &minor),
                                                    (to_string(major) + "." + to_string(minor)).c_str());
    
    free_identity(carol);
    free_message(msg);
    free_message(enc_msg);
    TEST_ASSERT(true);
}

void Message2_1Tests::check_message2_1_recip_1_0_from_msg_OpenPGP() {
    pEp_identity* alice = NULL;
    
    PEP_STATUS status = set_up_preset(session, ALICE, 
                                      true, true, true, true, true, &alice);

    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(alice);

    // receive 1.0 message from OpenPGP
    string incoming = slurp("test_mails/From_M1_0.eml");
    
    char* dec_msg;
    char* mod_src;
    PEP_decrypt_flags_t flags = 0;
    stringlist_t* keylist_used = NULL;
    PEP_rating rating;
    
    status = MIME_decrypt_message(session, incoming.c_str(), incoming.size(), &dec_msg, &keylist_used, &rating, &flags, &mod_src);

    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    // generate message
    
    message* msg = new_message(PEP_dir_outgoing);
    
    msg->from = alice;
    msg->to = new_identity_list(new_identity("pep-test-carol@pep-project.org", NULL, NULL, NULL));
    msg->shortmsg = strdup("Boom shaka laka");
    msg->longmsg = strdup("Don't you get sick of these?");
    
    message* enc_msg = NULL;

    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    TEST_ASSERT(status == PEP_STATUS_OK);
    
    // ensure sent message is in 1.0 format
    unsigned int major = 1;
    unsigned int minor = 0;
    TEST_ASSERT_MSG(verify_message_version_produced(enc_msg, &major, &minor),
                                                    (to_string(major) + "." + to_string(minor)).c_str());
    
    free_message(msg);
    free_message(enc_msg);
    free(dec_msg);
    free(mod_src);
    TEST_ASSERT(true);
}

void Message2_1Tests::check_message2_1_recip_2_0_from_msg() {
    // receive 2.0 message
    TEST_ASSERT(true);
}

void Message2_1Tests::check_message2_1_recip_2_1_from_msg() {
    // receive 2.1 message

    // generate message
    
    // ensure sent message is in 2.1 format

    TEST_ASSERT(true);
}

void Message2_1Tests::check_message2_1_recip_mixed_2_0() {
    // Set mixed recipient values

    // generate message
    
    // ensure sent message is in 2.0 format

    TEST_ASSERT(true);
}

void Message2_1Tests::check_message2_1_recip_mixed_1_0_OpenPGP() {
    // Set mixed recipient values

    // generate message
    
    // ensure sent message is in 1.0 format

    TEST_ASSERT(true);
}
