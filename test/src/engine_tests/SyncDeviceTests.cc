// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>

#include <cpptest.h>

#include <cstring>

#include "pEpEngine.h"

#include "TestUtils.h"

#include "pEpTestDevice.h"

#include "EngineTestIndividualSuite.h"
#include "SyncDeviceTests.h"

using namespace std;

SyncDeviceTests::SyncDeviceTests(string suitename, string test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("SyncDeviceTests::check_sync_device"),
                                                                      static_cast<Func>(&SyncDeviceTests::check_sync_device)));
}

void SyncDeviceTests::check_sync_device() {
    TEST_ASSERT(true);
}

