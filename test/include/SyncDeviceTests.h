// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef SYNC_DEVICE_H
#define SYNC_DEVICE_H

#include <string>
#include "EngineTestIndividualSuite.h"

using namespace std;

class SyncDeviceTests : public EngineTestIndividualSuite {
    public:
        SyncDeviceTests(string test_suite, string test_home_dir);
                
    private:
        void check_sync_device();
};

#endif
