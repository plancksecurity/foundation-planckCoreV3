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
#include "pEpTestStatic.h"

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

    // Note: THIS IS BRITTLE. If you're trying on a new platform and it fails, it's because C++ names may be mangled differently
    // and other platforms may have other requirements. Start by checking maximum socket path lengths...
    // We need at least size for 3 chars of unique class dir, 3 chars of test number, 5 chars for "gnupg", for "S.gpg-agent", plus
    // slashes. This is really just because gpg-agent fails on MacOS because of a shorter sun_path max.
    
    // fixme = "gnupg" needs to be made central
    string keypath_str = "gnupg";

    if (common_test_home.size() > pEpTestStatic::getAvailablePathChars(keypath_str)) {
        cerr << "Test home path size too long. Please notify the devs that this finally broke." 
             << " In the meantime, try modifying common_test_home here in TestDriver.cc and hope nothing breaks" << endl;
        throw -127;
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

    Test::Output* output = new Test::pEpTestOutput(); // blah
    return test_runner->run(*output, false) ? 0 : 1;
    delete(output);
}
