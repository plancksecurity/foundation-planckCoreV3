// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef G_P_G_CONF_FIX_H
#define G_P_G_CONF_FIX_H

#include <string>
#include "EngineTestIndividualSuite.h"

using namespace std;

class GPGConfFixTests : public EngineTestIndividualSuite {
    public:
        GPGConfFixTests(string test_suite, string test_home_dir);

    protected:
	void setup();

    private:
        void check_g_p_g_conf_fix();
};

#endif
