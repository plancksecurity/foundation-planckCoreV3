#include <cpptest.h>
#include <cpptest-suite.h>
#include <cpptest-textoutput.h>
#include <string>
#include <sys/stat.h>
#include <errno.h>
#include "EngineTestSuite.h"
#include "EngineTestIndividualSuite.h"
#include "EngineTestSessionSuite.h"
#include "SuiteMaker.h"

// Begin where we should generate stuff
#include "DecorateTests.h"

using namespace std;

void suitemaker_build(const char* test_class_name, const char* test_home, std::auto_ptr<Test::Suite>& test_suite) {
    if (strcmp(test_class_name, "DecorateTests") == 0)
        test_suite = auto_ptr<Test::Suite> (new DecorateTests(test_class_name, test_home));
}
