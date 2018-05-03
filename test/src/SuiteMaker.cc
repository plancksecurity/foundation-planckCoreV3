#include <cpptest.h>
#include <cpptest-suite.h>
#include <memory>
#include <vector>


// Begin where we should generate stuff
#include "DecorateTests.h"
#include "AppleMailTests.h"

#include "SuiteMaker.h"

const char* SuiteMaker::all_suites[] = {
    "DecorateTests",
    "AppleMailTests"
};

// This file is generated, so magic constants are ok.
int SuiteMaker::num_suites = 2;

void SuiteMaker::suitemaker_build(const char* test_class_name, const char* test_home, Test::Suite** test_suite) {
    if (strcmp(test_class_name, "DecorateTests") == 0)
        *test_suite = new DecorateTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "AppleMailTests") == 0)
        *test_suite = new AppleMailTests(test_class_name, test_home);    
}

void SuiteMaker::suitemaker_buildlist(const char** test_class_names, int num_to_run, const char* test_home, std::vector<Test::Suite*>& test_suites) {
    for (int i = 0; i < num_to_run; i++) {
        Test::Suite* suite = NULL;
        SuiteMaker::suitemaker_build(test_class_names[i], test_home, &suite);
        if (!suite)
            throw std::runtime_error("Could not create a test suite instance."); // FIXME, better error, cleanup, obviously
        test_suites.push_back(suite);
    }    
}

void SuiteMaker::suitemaker_buildall(const char* test_home, std::vector<Test::Suite*>& test_suites) {
    SuiteMaker::suitemaker_buildlist(SuiteMaker::all_suites, SuiteMaker::num_suites, test_home, test_suites);
}
