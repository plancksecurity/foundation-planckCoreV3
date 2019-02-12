#ifndef ENGINE_TEST_INDIVIDUAL_SUITE_H
#define ENGINE_TEST_INDIVIDUAL_SUITE_H

#include <cpptest.h>
#include <cpptest-suite.h>
#include <cpptest-textoutput.h>
#include <string>
#include "pEpEngine.h"
#include "EngineTestSuite.h"

using namespace std;

class EngineTestIndividualSuite : public EngineTestSuite {
    public:
        EngineTestIndividualSuite(string suitename, string test_home_dir,
                                  bool make_default_device = true);
        virtual ~EngineTestIndividualSuite();
    protected:
        virtual void setup();
        virtual void tear_down();
};
#endif
