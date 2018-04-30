#include <cpptest.h>
#include <cpptest-suite.h>
#include <cpptest-textoutput.h>
#include <stdlib.h>
#include <unistd.h>
#include <ftw.h>

#include "EngineTestSuite.h"
#include "EngineTestSessionSuite.h"

using namespace std;

// Constructor
EngineTestSessionSuite::EngineTestSessionSuite(string suitename, string test_home_dir) 
    : EngineTestSuite(suitename, test_home_dir) {
    set_full_env();
}

EngineTestSessionSuite::~EngineTestSessionSuite() {
    restore_full_env();
}
