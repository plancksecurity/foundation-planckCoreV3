// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>

#include "pEpEngine.h"
#include "test_util.h"

#include "EngineTestIndividualSuite.h"
#include "MessageNullFromTests.h"

using namespace std;

MessageNullFromTests::MessageNullFromTests(string suitename, string test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("MessageNullFromTests::check_message_null_from_no_header_key_unencrypted"),
                                                                      static_cast<Func>(&MessageNullFromTests::check_message_null_from_no_header_key_unencrypted)));
}

void MessageNullFromTests::check_message_null_from_no_header_key_unencrypted() {
    string null_from_msg = slurp("test_files/432_no_from_2.eml");
    cout << null_from_msg << endl;
    stringlist_t* keylist = NULL;
    PEP_decrypt_flags_t flags;
    PEP_rating rating;
    char* mime_plaintext = NULL;
    char* modified_src = NULL;
    PEP_STATUS status = MIME_decrypt_message(session, null_from_msg.c_str(),
                                             null_from_msg.size(),
                                             &mime_plaintext,
                                             &keylist,
                                             &rating,
                                             &flags,
                                             &modified_src);
    TEST_ASSERT_MSG(status == PEP_UNENCRYPTED, tl_status_string(status));                                         
}

