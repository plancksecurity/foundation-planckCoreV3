// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef SYNC_DEVICE_H
#define SYNC_DEVICE_H

#include <string>
#include <vector>
#include "EngineTestIndividualSuite.h"
#include "pEpTestDevice.h"

using namespace std;

class SyncDeviceTests : public EngineTestIndividualSuite {
    public:
        SyncDeviceTests(string test_suite, string test_home_dir);
        
        vector<pEpTestDevice*> device_queue;

    protected:
        void setup();
        void tear_down();        
    private:
        void check_sync_two_devices();
        void check_sync_three_devices();
        void check_sync_two_grouped_devices();
};

#endif
