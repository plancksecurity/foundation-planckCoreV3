// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef DEVICE_MODEL_H
#define DEVICE_MODEL_H

#include <string>
#include "EngineTestIndividualSuite.h"

using namespace std;

class DeviceModelTests : public EngineTestIndividualSuite {
    public:
        DeviceModelTests(string test_suite, string test_home_dir);
    private:
        void check_device_model();
        void check_two_device_model();
        void check_two_device_functionality();
};

#endif
