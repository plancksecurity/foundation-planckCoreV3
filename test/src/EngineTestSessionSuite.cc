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
    : EngineTestSuite(suitename, test_home_dir) {}

EngineTestSessionSuite::~EngineTestSessionSuite() {}

void EngineTestSessionSuite::setup() {
    EngineTestSuite::setup();
    if (on_test_number == 1)
        set_full_env();
}

void EngineTestSessionSuite::tear_down() {
    if (on_test_number == number_of_tests)
        restore_full_env();
        
    EngineTestSuite::tear_down();
}
