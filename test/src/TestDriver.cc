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

string common_test_home = "~/pEp_tests";

void usage() {
    throw "Bad usage. Fix me, you loser developer.";
}

int main(int argc, char** argv) {
    const int MIN_ARGC = 1;
    if (argc < MIN_ARGC)
        usage();

    int start_index = 1;
    

    if (argc > 1) {
        string tmpstr = argv[1];
        if (tmpstr.compare(0,10,"--testdir=")) {
            try {
                tmpstr = tmpstr.substr(10);
            } 
            catch (std::out_of_range o) {
                usage();
            }
            common_test_home = tmpstr;
            start_index++;
        }
    }

    struct stat dirchk;
    if (stat(common_test_home.c_str(), &dirchk) == 0) {
        if (!S_ISDIR(dirchk.st_mode))
            throw ("The test directory, " + common_test_home + "exists, but is not a directory.").c_str(); 
    }
    else if (common_test_home.compare("~/pEp_tests")) {
        int errchk = mkdir(common_test_home.c_str(), S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
        if (errchk != 0)
            throw "Error creating a test directory.";
    }
    else
        throw "Test directory does not exist. Test directories from the command line must be created first. Because we're lazy.";
        
            
    EngineTestSuite* test_runner = new EngineTestSuite("MainTestDriver", common_test_home);
        
    for (int i = start_index; i < argc; i++) {
        char* curr_arg = argv[i];
        auto_ptr<Test::Suite> test_suite;
        suitemaker_build(argv[i], common_test_home.c_str(), test_suite);
        if (test_suite.get() == NULL)
            throw "Could not create a test suite instance."; // FIXME, better error, cleanup, obviously
        test_runner->add(test_suite);
    }

    Test::TextOutput output(Test::TextOutput::Terse);
    return test_runner->run(output) ? 1 : 0;
    
}
