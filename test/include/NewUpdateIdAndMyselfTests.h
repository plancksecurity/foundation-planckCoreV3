// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef NEW_UPDATE_ID_AND_MYSELF_H
#define NEW_UPDATE_ID_AND_MYSELF_H

#include <string>
#include "EngineTestSessionSuite.h"

using namespace std;

class NewUpdateIdAndMyselfTests : public EngineTestSessionSuite {
    public:
        NewUpdateIdAndMyselfTests(string test_suite, string test_home_dir);
    private:
        void check_new_update_id_and_myself();
};

#endif
