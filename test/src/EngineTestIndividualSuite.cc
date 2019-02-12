#include "TestConstants.h"
#include <cpptest.h>
#include <cpptest-suite.h>
#include <cpptest-textoutput.h>
#include <stdlib.h>
#include <unistd.h>
#include <ftw.h>

#include "EngineTestSuite.h"
#include "EngineTestIndividualSuite.h"

using namespace std;

// Constructor
EngineTestIndividualSuite::EngineTestIndividualSuite(string suitename, 
                                                     string test_home_dir,
                                                     bool make_default_device) 
    : EngineTestSuite(suitename, test_home_dir, make_default_device) { 
}

EngineTestIndividualSuite::~EngineTestIndividualSuite() {
    
}

void EngineTestIndividualSuite::setup() {
    EngineTestSuite::setup();
    set_full_env(); // This will be called by default before every test
}

void EngineTestIndividualSuite::tear_down() {
    restore_full_env();
    EngineTestSuite::tear_down();
}
