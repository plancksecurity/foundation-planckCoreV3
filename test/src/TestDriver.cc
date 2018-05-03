#include <stdlib.h>
#include <cpptest.h>
#include <cpptest-suite.h>
#include <cpptest-textoutput.h>
#include <string>
#include <vector>
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

int main(int argc, const char** argv) {
    const int MIN_ARGC = 1;
    if (argc < MIN_ARGC)
        usage();
    
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

    std::vector<Test::Suite*> suites_to_run;
    
    if (argc == MIN_ARGC)
        SuiteMaker::suitemaker_buildall(common_test_home.c_str(), suites_to_run);
    else
        SuiteMaker::suitemaker_buildlist(&argv[1], argc - MIN_ARGC, common_test_home.c_str(), suites_to_run);
        
    for (std::vector<Test::Suite*>::iterator it = suites_to_run.begin(); it != suites_to_run.end(); ++it) {
        auto_ptr<Test::Suite> suite(*it);
        test_runner->add(suite); 
    }

    Test::TextOutput output(Test::TextOutput::Terse);
    return test_runner->run(output) ? 1 : 0;
    
}
