// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef CHECK_RENEWED_EXPIRED_KEY_TRUST_STATUS_H
#define CHECK_RENEWED_EXPIRED_KEY_TRUST_STATUS_H

#include <string>
#include "EngineTestIndividualSuite.h"

using namespace std;

class CheckRenewedExpiredKeyTrustStatusTests : public EngineTestIndividualSuite {
    public:
        CheckRenewedExpiredKeyTrustStatusTests(string test_suite, string test_home_dir);
    private:
        void check_renewed_expired_key_trust_status();
        void check_renewed_expired_key_trust_status_trusted_user();
        void check_renewed_expired_key_trust_status_pEp_user();
        void check_renewed_expired_key_trust_status_trusted_pEp_user();        
};

#endif
