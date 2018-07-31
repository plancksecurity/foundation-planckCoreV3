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
        void check_conf_fix_broken_conf_old_db_0();
        void check_conf_fix_broken_conf_old_db_1();
        void check_conf_fix_broken_conf_old_db_2();
        void check_conf_fix_broken_conf_old_db_3();
        void check_conf_fix_broken_conf_old_db_4();
        void check_conf_fix_broken_conf_old_db_5();
        void check_conf_fix_broken_conf_old_db_6();        
        void check_conf_fix_broken_agent_conf_old_db_0();
        void check_conf_fix_broken_agent_conf_old_db_1();
        void check_conf_fix_broken_agent_conf_old_db_2();
        void check_conf_fix_broken_agent_conf_old_db_3();
        void check_conf_fix_broken_agent_conf_old_db_4();
        void check_conf_fix_broken_agent_conf_old_db_5();
        void check_conf_fix_broken_agent_conf_old_db_6();                
};

#endif
