#ifndef ENGINE_TEST_SESSION_SUITE_H
#define ENGINE_TEST_SESSION_SUITE_H

#include <cpptest.h>
#include <cpptest-suite.h>
#include <cpptest-textoutput.h>
#include <string>
#include "pEpEngine.h"

using namespace std;

class EngineTestSessionSuite : public EngineTestSuite {
    public:
        EngineTestSessionSuite(string suitename, string test_home_dir);
        virtual ~EngineTestSessionSuite();
        
        virtual void setup();
        virtual void tear_down();
};
#endif
