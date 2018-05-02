// This file is under GNU General Public License 3.0
// see LICENSE.txt
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

// Begin where we generate stuff
#include "DecorateTests.h"
#include "AppleMailTests.h"


using namespace std;

static const char* const all_suites[] = {
    "DecorateTests",
    "AppleMailTests",
};

void suitemaker_build(const char* test_class_name, const char* test_home, std::auto_ptr<Test::Suite>& test_suite) {
    if (strcmp(test_class_name, "DecorateTests") == 0)
        test_suite = auto_ptr<Test::Suite> (new DecorateTests(test_class_name, test_home));
    else if (strcmp(test_class_name, "AppleMailTests") == 0)
        test_suite = auto_ptr<Test::Suite> (new AppleMailTests(test_class_name, test_home));
}
