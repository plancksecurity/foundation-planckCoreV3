// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef GET_KEY_RATING_FOR_USER_H
#define GET_KEY_RATING_FOR_USER_H

#include <string>
#include "EngineTestIndividualSuite.h"

using namespace std;

class GetKeyRatingForUserTests : public EngineTestIndividualSuite {
    public:
        GetKeyRatingForUserTests(string test_suite, string test_home_dir);
    private:
        void check_get_key_rating_for_user();
};

#endif
