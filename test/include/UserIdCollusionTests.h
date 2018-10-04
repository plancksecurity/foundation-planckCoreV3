// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef USER_ID_COLLUSION_H
#define USER_ID_COLLUSION_H

#include <string>
#include "EngineTestIndividualSuite.h"

using namespace std;

class UserIdCollusionTests : public EngineTestIndividualSuite {
    public:
        UserIdCollusionTests(string test_suite, string test_home_dir);
    private:
        void check_user_id_collusion();
};

#endif
