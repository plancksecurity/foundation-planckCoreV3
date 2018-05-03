// This file is under GNU General Public License 3.0
// see LICENSE.txt

//
// src/SuiteMaker.cc generated by gensuitemaker.py - changes may be overwritten. You've been warned!
//

#include <cpptest.h>
#include <cpptest-suite.h>
#include <memory>
#include <vector>
#include "SuiteMaker.h"

// Begin where we generate stuff
#include "DecorateTests.h"
#include "AppleMailTests.h"
#include "CaseAndDotAddressTests.h"
#include "SequenceTests.h"
#include "StringpairListTests.h"
#include "BloblistTests.h"
#include "StringlistTests.h"
#include "TrustwordsTests.h"
#include "TrustManipulationTests.h"
#include "UserIDAliasTests.h"


const char* SuiteMaker::all_suites[] = {
    "DecorateTests",
    "AppleMailTests",
    "CaseAndDotAddressTests",
    "SequenceTests",
    "StringpairListTests",
    "BloblistTests",
    "StringlistTests",
    "TrustwordsTests",
    "TrustManipulationTests",
    "UserIDAliasTests",
};

// This file is generated, so magic constants are ok.
int SuiteMaker::num_suites = 10;

void SuiteMaker::suitemaker_build(const char* test_class_name, const char* test_home, Test::Suite** test_suite) {
    if (strcmp(test_class_name, "DecorateTests") == 0)
        *test_suite = new DecorateTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "AppleMailTests") == 0)
        *test_suite = new AppleMailTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "CaseAndDotAddressTests") == 0)
        *test_suite = new CaseAndDotAddressTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "SequenceTests") == 0)
        *test_suite = new SequenceTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "StringpairListTests") == 0)
        *test_suite = new StringpairListTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "BloblistTests") == 0)
        *test_suite = new BloblistTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "StringlistTests") == 0)
        *test_suite = new StringlistTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "TrustwordsTests") == 0)
        *test_suite = new TrustwordsTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "TrustManipulationTests") == 0)
        *test_suite = new TrustManipulationTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "UserIDAliasTests") == 0)
        *test_suite = new UserIDAliasTests(test_class_name, test_home);
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

