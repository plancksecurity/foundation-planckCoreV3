#include <stdlib.h>
#include <unistd.h>
#include <ftw.h>

#include "EngineTestSuite.h"
using namespace std;

// Constructor
EngineTestSessionSuite::EngineTestSessionSuite(string suitename, string test_home_dir) :
    EngineTestSuite::EngineTestSuite(suitename, test_home_dir) {
    set_full_env();
}

EngineTestSessionSuite::~EngineTestSessionSuite() {
    restore_full_env();
}
