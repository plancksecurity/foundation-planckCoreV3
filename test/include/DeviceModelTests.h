// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef DEVICE_MODEL_H
#define DEVICE_MODEL_H

#include <string>
#include <vector>
#include "EngineTestIndividualSuite.h"

using namespace std;

class DeviceModelTests : public EngineTestIndividualSuite {
    public:
        DeviceModelTests(string test_suite, string test_home_dir);

    protected:
        void tear_down();
        
    private:
        void check_device_model();
        void check_two_device_model();
        void check_two_device_functionality();
        void check_mbox();
        void check_shared_mbox();
        
        void clear_and_delete_devices();
        
        vector<pEpTestDevice*> devices;
};

#endif
