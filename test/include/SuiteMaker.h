#ifndef SUITEMAKER_H
#define SUITEMAKER_H

#include <cpptest.h>
#include <cpptest-suite.h>
#include <memory>
#include <vector>

#include "EngineTestSuite.h"

class SuiteMaker {
    public:
        static void suitemaker_build(const char* test_class_name, const char* test_home, Test::Suite** test_suite);
        static void suitemaker_buildall(const char* test_home, std::vector<Test::Suite*>& test_suites);
        static void suitemaker_buildlist(const char** test_class_names, int num_to_run, const char* test_home, std::vector<Test::Suite*>& test_suites);

    private:
        static int num_suites;
        static const char* all_suites[];
};

#endif
