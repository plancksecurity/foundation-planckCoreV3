// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <cstring>
#include <string>

#include <cpptest.h>
#include "test_util.h"

#include "pEpEngine.h"

#include "EngineTestIndividualSuite.h"
#include "IOS1664Tests.h"
#include "mime.h"

using namespace std;

IOS1664Tests::IOS1664Tests(string suitename, string test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("IOS1664Tests::check_i_o_s1664"),
                                                                      static_cast<Func>(&IOS1664Tests::check_i_o_s1664)));
}

void IOS1664Tests::check_i_o_s1664() {
    string email = slurp("test_mails/0.47.eml");
    TEST_ASSERT(!email.empty());
    
    message* message_mail = NULL;
    bool raise_att;
    
    PEP_STATUS status = _mime_decode_message_internal(email.c_str(), email.size(), &message_mail, &raise_att);
    TEST_ASSERT(status == PEP_STATUS_OK && message_mail);
    
    // create own identity here, because we want to reply, before we start.
    pEp_identity* me = new_identity("android01@peptest.ch", NULL, PEP_OWN_USERID, NULL);
    status = myself(session, me);
    
    TEST_ASSERT(status == PEP_STATUS_OK && me->fpr != NULL && me->fpr[0] != '\0');
    
    // Ok, now read the message
    message* read_message = NULL;
    stringlist_t* keylist;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    
    status = decrypt_message(session, message_mail, &read_message, &keylist, &rating, &flags);
    TEST_ASSERT(status == PEP_UNENCRYPTED);
    
    pEp_identity* you = new_identity("superxat@gmail.com", NULL, NULL, NULL);
    
    // N.B. while obviously it would be better to write the test expecting us to 
    // accept the key, I'm actually testing that we don't get the wrong status
    // based on the presumption of rejection
    
    message* out_msg = new_message(PEP_dir_outgoing);
    out_msg->from = me;
    out_msg->to = new_identity_list(you);
    out_msg->shortmsg = strdup("Hussidente 2020!");
    out_msg->longmsg = strdup("A Huss in every office!");
    
    status = identity_rating(session, out_msg->from, &rating);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT_MSG(rating == PEP_rating_trusted_and_anonymized, tl_rating_string(rating));
    status = identity_rating(session, out_msg->to->ident, &rating);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT_MSG(rating == PEP_rating_reliable, tl_rating_string(rating));

    status = outgoing_message_rating(session, out_msg, &rating);
    TEST_ASSERT(rating == PEP_rating_reliable);
    
    TEST_ASSERT(true);
}
