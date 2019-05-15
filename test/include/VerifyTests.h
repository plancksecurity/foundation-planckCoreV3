// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef VERIFY_H
#define VERIFY_H

#include <string>
#include "EngineTestIndividualSuite.h"

using namespace std;

class VerifyTests : public EngineTestIndividualSuite {
    public:
        VerifyTests(string test_suite, string test_home_dir);
    private:
        static constexpr const char *mary_fpr = "599B3D67800DB37E2DCE05C07F59F03CD04A226E";
        void check_revoked_tpk();
        void check_revoked_signing_key();
        void check_expired_tpk();
        void check_expired_signing_key();
};

#endif
