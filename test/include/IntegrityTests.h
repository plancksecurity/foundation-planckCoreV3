// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef INTEGRITY_H
#define INTEGRITY_H

#include <string>
#include "pEpEngine.h"
#include "message_api.h"

#include "EngineTestIndividualSuite.h"

using namespace std;

class IntegrityTests : public EngineTestIndividualSuite {
    public:
        IntegrityTests(string test_suite, string test_home_dir);
        
    protected:
        void setup();
        void tear_down();
            
    private:
        const char* recip_fpr;

        // used by each test
        string message;
        char* decrypted_msg;
        PEP_STATUS decrypt_status;
        PEP_rating rating;
        PEP_decrypt_flags_t flags;
        stringlist_t* keylist;
        char* dummy_ignore;
        
        void check_unsigned_PGP_MIME();
        void check_unsigned_PGP_MIME_attached_key();
        void check_unsigned_PGP_MIME_w_render_flag();
        void check_known_good_signed_PGP_MIME();
        void check_known_good_signed_PGP_MIME_attached_key();
        void check_unknown_signed_PGP_MIME_no_key();
        void check_unknown_signed_PGP_MIME_attached_key();
        void check_unsigned_PGP_MIME_corrupted();
        void check_signed_PGP_MIME_corrupted();
        void check_unsigned_2_0();
        void check_unknown_signed_2_0_no_key();
        void check_unknown_signed_2_0_no_key_known_signer();
        void check_unknown_signed_2_0_key_attached();

        void check_integrity();
        

};

#endif
