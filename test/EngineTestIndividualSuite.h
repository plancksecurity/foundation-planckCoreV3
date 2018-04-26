#ifndef ENGINE_INDIVIDUAL_SESSION_SUITE_H
#define ENGINE_INDIVIDUAL_SESSION_SUITE_H

#include <cpptest-suite.h>
#include <string>
#include "pEpEngine.h"

using namespace std;

class EngineTestIndividualSuite : public EngineTestSuite {
    public:
        EngineIndividualTestSuite(string suitename, string test_home_dir);
        ~EngineIndividualTestSuite();
};
#endif
