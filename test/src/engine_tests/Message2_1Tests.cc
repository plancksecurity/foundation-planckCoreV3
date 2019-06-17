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
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("Message2_1Tests::check_message2_1"),
                                                                      static_cast<Func>(&Message2_1Tests::check_message2_1)));
}

static bool verify_message_version_produced(message* enc_msg, unsigned int* maj_inout, unsigned it* min_inout) {
    if (!maj_inout || !min_inout)
        return false;
    int major = *maj_inout;
    int minor = *min_inout;
    
    char* ptext = NULL;
    size_t psize = 0;
    stringlist_t* keylist = NULL;
    
    PEP_STATUS status = cryptotech[crypto].decrypt_and_verify(session, enc_msg->attachments->next->value,
                                                              enc_msg->attachments->next->size, NULL, 0,
                                                              &ptext, &psize, &_keylist,
                                                              NULL);

    // fixme, check status
    if (strstr(ptext, "pEp-Wrapped-Message-Info: OUTER") != NULL && strstr(ptext, "pEp-Wrapped-Message-Info: OUTER") != NULL) {
        *maj_inout = 2;
        *min_inout = 1;
    }
    else if (strstr(ptext, "X-pEp-Wrapped-Message-Info: INNER") != NULL && strstr(ptext, "forwarded=no") != NULL) {
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
    TEST_ASSERT(slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc"));
    TEST_ASSERT(slurp_and_import_key(session, "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc"));    

    // default should be 2.0 after setting pep status
    
    // generate message
    
    // ensure sent message is in 2.0 format
    TEST_ASSERT(true);
}

void Message2_1Tests::check_message2_1_recip_1_0() {
    // set recip to 1.0
    
    // generate message
    
    // ensure sent message is in 1.0 format
    
    TEST_ASSERT(true);
}

void Message2_1Tests::check_message2_1_recip_1_0_OpenPGP() {
    // set recip to 1.0
    
    // generate message
    
    // ensure sent message is in 1.0 format
    
    TEST_ASSERT(true);
}

void Message2_1Tests::check_message2_1_recip_2_1() {
    // set recip to 2.1
    
    // generate message
    
    // ensure sent message is in 2.1 format
    
    
    TEST_ASSERT(true);
}

void Message2_1Tests::check_message2_1_recip_1_0_from_msg() {
    // receive 1.0 message

    // generate message
    
    // ensure sent message is in 1.0 format

    TEST_ASSERT(true);
}

void Message2_1Tests::check_message2_1_recip_1_0_from_msg_OpenPGP() {
    // receive 1.0 message from OpenPGP

    // generate message
    
    // ensure sent message is in 1.0 format

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

void Message2_1Tests::check_message2_1_recip_mixed_1_0() {
    // Set mixed recipient values

    // generate message
    
    // ensure sent message is in 1.0 format

    TEST_ASSERT(true);
}

void Message2_1Tests::check_message2_1_recip_mixed_1_0_OpenPGP() {
    // Set mixed recipient values

    // generate message
    
    // ensure sent message is in 1.0 format

    TEST_ASSERT(true);
}
