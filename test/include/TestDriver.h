#ifndef PEP_TEST_DRIVER_H
#define PEP_TEST_DRIVER_H

#include <cpptest.h>
#include <cpptest-suite.h>
#include <cpptest-textoutput.h>
#include <string>
#include <map>
#include "SuiteMaker.h"
#include "EngineTestSuite.h"
#include "EngineTestIndividualSuite.h"
#include "EngineTestSessionSuite.h"

using namespace std;

typedef map<string, EngineTestSuite> SuiteMap;
typedef set<string> NameSet;

#endif
