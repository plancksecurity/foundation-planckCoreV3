#ifndef ENGINE_TEST_H

#include <cpptest-suite.h>
#include <string>
#include "pEpEngine.h"

using namespace std;

class EngineTest : public Test::Suite {
    public:
        EngineTest();
        EngineTest(string suitename, string test_home_dir);
        
    protected:
        PEP_SESSION session;
        string test_home;
        string prev_gpg_home;
        string name;
        
        virtual void setup();
        virtual void tear_down();
        void set_full_env();
        void restore_full_env();
        void initialise_test_home();
        
    private:
        static int util_delete_filepath(const char *filepath, 
                                        const struct stat *file_stat, 
                                        int ftw_info, 
                                        struct FTW * ftw_struct);
};
#endif
