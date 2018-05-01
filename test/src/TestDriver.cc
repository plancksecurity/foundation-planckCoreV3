#include <stdlib.h>
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

using namespace std;

string common_test_home = "./pEp_test_home";

void usage() {
    throw std::runtime_error("Bad usage. Fix me, you loser developer.");
}

int main(int argc, char** argv) {
    const int MIN_ARGC = 1;
    if (argc < MIN_ARGC)
        usage();

    int start_index = 1;
    
    struct stat dirchk;
    if (stat(common_test_home.c_str(), &dirchk) == 0) {
        if (!S_ISDIR(dirchk.st_mode))
            throw std::runtime_error(("The test directory, " + common_test_home + "exists, but is not a directory.").c_str()); 
    }
    else {
        int errchk = mkdir(common_test_home.c_str(), S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
        cout << errchk << endl;
        if (errchk != 0)
            throw std::runtime_error("Error creating a test directory.");
    }
                    
    EngineTestSuite* test_runner = new EngineTestSuite("MainTestDriver", common_test_home);
        
    for (int i = start_index; i < argc; i++) {
        char* curr_arg = argv[i];
        auto_ptr<Test::Suite> test_suite;
        suitemaker_build(argv[i], common_test_home.c_str(), test_suite);
        if (test_suite.get() == NULL)
            throw std::runtime_error("Could not create a test suite instance."); // FIXME, better error, cleanup, obviously
        test_runner->add(test_suite);
    }

    Test::TextOutput output(Test::TextOutput::Terse);
    return test_runner->run(output) ? 1 : 0;
    
}
