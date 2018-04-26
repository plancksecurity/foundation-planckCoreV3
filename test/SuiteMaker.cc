#include <cpptest-suite.h>
#include <string>
#include <sys/stat.h>
#include <errno.h>
#include "EngineTestSuite.h"
#include "EngineTestIndividualSuite.h"
#include "EngineTestSessionSuite.h"

// Begin where we should generate stuff
#include "DecorateTests.h"

static EngineTestSuite* build(const char* test_class_name, const char* test_home) {
    if (strcmp(test_class_name, "DecorateTests") == 0)
        return new DecorateTests(test_class_name, test_home);
    return NULL;
}
