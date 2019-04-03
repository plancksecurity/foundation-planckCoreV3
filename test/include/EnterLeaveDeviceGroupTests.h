// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef ENTER_LEAVE_DEVICE_GROUP_H
#define ENTER_LEAVE_DEVICE_GROUP_H

#include <string>
#include "EngineTestIndividualSuite.h"

using namespace std;

class EnterLeaveDeviceGroupTests : public EngineTestIndividualSuite {
    public:
        EnterLeaveDeviceGroupTests(string test_suite, string test_home_dir);
    private:
        void check_enter_device_group_no_own();    
        void check_enter_device_group_one_own_empty();    
        void check_enter_device_group_one_own_one();    
        void check_enter_device_group_one_reversed_by_many();    
        void check_enter_device_group_one_own_single_not_me();    
        void check_enter_device_group_one_own_single_many_w_not_me();    
        void check_enter_device_group_many_empty();    
        void check_enter_device_group_many_own_add_explicit();
        void check_enter_device_group_many_own_one();    
        void check_enter_device_group_many_own_many();    
        void check_enter_device_group_many_own_many_w_not_me();    
};

#endif
