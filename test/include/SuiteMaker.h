#ifndef SUITEMAKER_H
#define SUITEMAKER_H

#include <cpptest.h>
#include <cpptest-suite.h>
#include <cpptest-textoutput.h>
#include <string>
#include <sys/stat.h>
#include <errno.h>
#include "EngineTestSuite.h"
#include "EngineTestIndividualSuite.h"
#include "EngineTestSessionSuite.h"

// Begin where we should generate stuff
#include "DecorateTests.h"

void suitemaker_build(const char* test_class_name, const char* test_home, std::auto_ptr<Test::Suite>& test_suite);

#endif
