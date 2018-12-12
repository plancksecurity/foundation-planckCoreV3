#include <stdlib.h>
#include <cpptest.h>
#include <cpptest-suite.h>
#include <cpptest-output.h>
#include "pEpTestOutput.h"

#include <string>
#include <vector>
#include <sys/stat.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <ftw.h>
#include "EngineTestSuite.h"
#include "EngineTestIndividualSuite.h"
#include "EngineTestSessionSuite.h"
#include "SuiteMaker.h"

using namespace std;

string common_test_home;

void usage() {
    throw std::runtime_error("Bad usage. Fix me, you loser developer.");
}

int main(int argc, const char** argv) {
    const int MIN_ARGC = 1;
    if (argc < MIN_ARGC)
        usage();
    
    size_t BUF_MAX_PATHLEN = 4097; 
    char buf[BUF_MAX_PATHLEN];// Linux max path size...
                          
    string curr_wd = getcwd(buf, BUF_MAX_PATHLEN);
    
    if (curr_wd.empty())
        throw std::runtime_error("Error grabbing current working directory"); 

    common_test_home = curr_wd + "/pEp_test_home";    
    
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

    Test::Output* output = new Test::pEpTestOutput(); // blah
    int result = test_runner->run(*output, false) ? 0 : -1;

    delete(output);
    delete(test_runner);

    return result;
}
