#include <stdlib.h>
#include <cpptest.h>
#include <cpptest-suite.h>
#include <cpptest-textoutput.h>
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

string common_test_home = "./pEp_test_home";

void usage() {
    throw std::runtime_error("Bad usage. Fix me, you loser developer.");
}

int util_delete_filepath(const char *filepath, 
                         const struct stat *file_stat, 
                         int ftw_info, 
                         struct FTW * ftw_struct) {
    int retval = 0;
    switch (ftw_info) {
        case FTW_DP:
            retval = rmdir(filepath);
            break;
        case FTW_F:
        case FTW_SLN:
            retval = unlink(filepath);
            break;    
        default:
            retval = -1;
    }
    
    return retval;
}


int main(int argc, const char** argv) {
    const int MIN_ARGC = 1;
    if (argc < MIN_ARGC)
        usage();
    
    struct stat dirchk;
    if (stat(common_test_home.c_str(), &dirchk) == 0) {
        if (!S_ISDIR(dirchk.st_mode))
            throw std::runtime_error(("The test directory, " + common_test_home + "exists, but is not a directory.").c_str()); 
                    
        struct stat buf;

        if (stat(common_test_home.c_str(), &buf) == 0) {
            cout << common_test_home << " exists. We'll recursively delete. We hope we're not horking your whole system..." << endl;
            int success = nftw((common_test_home + "/.").c_str(), util_delete_filepath, 100, FTW_DEPTH);
        }
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

    Test::TextOutput output(Test::TextOutput::Verbose);
    return test_runner->run(output, false) ? 0 : 1;
    
}
