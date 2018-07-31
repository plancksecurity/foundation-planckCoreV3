// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <iostream>
#include <fstream>

#include "pEpEngine.h"

#include "EngineTestIndividualSuite.h"
#include "GPGConfFixTests.h"

using namespace std;

GPGConfFixTests::GPGConfFixTests(string suitename, string temp_test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, temp_test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("GPGConfFixTests::check_conf_fix_broken_conf_old_db_0"),
                                                                      static_cast<Func>(&GPGConfFixTests::check_conf_fix_broken_conf_old_db_0)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("GPGConfFixTests::check_conf_fix_broken_conf_old_db_1"),
                                                                      static_cast<Func>(&GPGConfFixTests::check_conf_fix_broken_conf_old_db_1)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("GPGConfFixTests::check_conf_fix_broken_conf_old_db_2"),
                                                                      static_cast<Func>(&GPGConfFixTests::check_conf_fix_broken_conf_old_db_2)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("GPGConfFixTests::check_conf_fix_broken_conf_old_db_3"),
                                                                      static_cast<Func>(&GPGConfFixTests::check_conf_fix_broken_conf_old_db_3)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("GPGConfFixTests::check_conf_fix_broken_conf_old_db_4"),
                                                                      static_cast<Func>(&GPGConfFixTests::check_conf_fix_broken_conf_old_db_4)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("GPGConfFixTests::check_conf_fix_broken_conf_old_db_5"),
                                                                      static_cast<Func>(&GPGConfFixTests::check_conf_fix_broken_conf_old_db_5)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("GPGConfFixTests::check_conf_fix_broken_conf_old_db_6"),
                                                                      static_cast<Func>(&GPGConfFixTests::check_conf_fix_broken_conf_old_db_6)));                                                                      
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("GPGConfFixTests::check_conf_fix_broken_agent_conf_old_db_0"),
                                                                      static_cast<Func>(&GPGConfFixTests::check_conf_fix_broken_agent_conf_old_db_0)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("GPGConfFixTests::check_conf_fix_broken_agent_conf_old_db_1"),
                                                                      static_cast<Func>(&GPGConfFixTests::check_conf_fix_broken_agent_conf_old_db_1)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("GPGConfFixTests::check_conf_fix_broken_agent_conf_old_db_2"),
                                                                      static_cast<Func>(&GPGConfFixTests::check_conf_fix_broken_agent_conf_old_db_2)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("GPGConfFixTests::check_conf_fix_broken_agent_conf_old_db_3"),
                                                                      static_cast<Func>(&GPGConfFixTests::check_conf_fix_broken_agent_conf_old_db_3)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("GPGConfFixTests::check_conf_fix_broken_agent_conf_old_db_4"),
                                                                      static_cast<Func>(&GPGConfFixTests::check_conf_fix_broken_agent_conf_old_db_4)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("GPGConfFixTests::check_conf_fix_broken_agent_conf_old_db_5"),
                                                                      static_cast<Func>(&GPGConfFixTests::check_conf_fix_broken_agent_conf_old_db_5)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("GPGConfFixTests::check_conf_fix_broken_agent_conf_old_db_6"),
                                                                      static_cast<Func>(&GPGConfFixTests::check_conf_fix_broken_agent_conf_old_db_6)));                                                                      
                                                                      
}

void GPGConfFixTests::setup() {
    EngineTestSuite::setup();
}

static bool file_bytes_equal(const char* file_path_1, const char* file_path_2) {
    ifstream f1(file_path_1);
    ifstream f2(file_path_2);

    char c1, c2;
    
    while (f1.get(c1)) {
        if (f2.get(c2)) {
            if (c1 != c2) {
                if (c1 == '\n' && c2 == ' ') {
                    if (f2.get(c2)) {
                        if (c1 == c2)
                            continue;
                    }    
                }
                else if (c2 == '\n' && c1 == ' ') {
                    if (f1.get(c1)) {
                        if (c1 == c2)
                            continue;
                    }                        
                }
                return false;
            }
        }
        else {
            if (c1 == '\n' || c1 == ' ') {
                while (f1.get(c1)) {
                    if (c2 == '\n' || c2 == ' ')
                        continue;
                    return false;
                }
            }
        }        
    }
    while (f2.get(c2)) {
        if (c2 == '\n' || c2 == ' ')
            continue;
        return false;
    }
    
    return true;
    
}

void GPGConfFixTests::check_conf_fix_broken_conf_old_db_0() {
    set_full_env("test_files/427_bad_gpg_conf_0", NULL, "test_files/427_old_db");
    TEST_ASSERT(file_bytes_equal("test_files/427_fixed_gpg_conf_0", (temp_test_home + "/.gnupg/gpg.conf").c_str()));
}

void GPGConfFixTests::check_conf_fix_broken_conf_old_db_1() {
    set_full_env("test_files/427_bad_gpg_conf_1", NULL, "test_files/427_old_db");    
    TEST_ASSERT(file_bytes_equal("test_files/427_fixed_gpg_conf_1", (temp_test_home + "/.gnupg/gpg.conf").c_str()));
    
}

void GPGConfFixTests::check_conf_fix_broken_conf_old_db_2() {
    set_full_env("test_files/427_bad_gpg_conf_2", NULL, "test_files/427_old_db");        
    TEST_ASSERT(file_bytes_equal("test_files/427_fixed_gpg_conf_2", (temp_test_home + "/.gnupg/gpg.conf").c_str()));    
}

void GPGConfFixTests::check_conf_fix_broken_conf_old_db_3() {
    set_full_env("test_files/427_bad_gpg_conf_3", NULL, "test_files/427_old_db");    
    TEST_ASSERT(file_bytes_equal("test_files/427_fixed_gpg_conf_3", (temp_test_home + "/.gnupg/gpg.conf").c_str()));    
}

void GPGConfFixTests::check_conf_fix_broken_conf_old_db_4() {
    set_full_env("test_files/427_bad_gpg_conf_4", NULL, "test_files/427_old_db");        
    TEST_ASSERT(file_bytes_equal("test_files/427_fixed_gpg_conf_4", (temp_test_home + "/.gnupg/gpg.conf").c_str()));    
}

void GPGConfFixTests::check_conf_fix_broken_conf_old_db_5() {
    set_full_env("test_files/427_bad_gpg_conf_5", NULL, "test_files/427_old_db");        
    TEST_ASSERT(file_bytes_equal("test_files/427_fixed_gpg_conf_5", (temp_test_home + "/.gnupg/gpg.conf").c_str()));    
}

void GPGConfFixTests::check_conf_fix_broken_conf_old_db_6() {
    set_full_env("test_files/427_bad_gpg_conf_6", NULL, "test_files/427_old_db");        
    TEST_ASSERT(file_bytes_equal("test_files/427_fixed_gpg_conf_6", (temp_test_home + "/.gnupg/gpg.conf").c_str()));    
}

void GPGConfFixTests::check_conf_fix_broken_agent_conf_old_db_0() {
    set_full_env(NULL, "test_files/450_bad_gpgagent_conf_0", "test_files/427_old_db");
    TEST_ASSERT(file_bytes_equal("test_files/450_good_gpgagent_conf_0", (temp_test_home + "/.gnupg/gpg-agent.conf").c_str()));
}

void GPGConfFixTests::check_conf_fix_broken_agent_conf_old_db_1() {
    set_full_env(NULL, "test_files/450_bad_gpgagent_conf_1", "test_files/427_old_db");    
    TEST_ASSERT(file_bytes_equal("test_files/450_good_gpgagent_conf_1", (temp_test_home + "/.gnupg/gpg-agent.conf").c_str()));
    
}

void GPGConfFixTests::check_conf_fix_broken_agent_conf_old_db_2() {
    set_full_env(NULL, "test_files/450_bad_gpgagent_conf_2", "test_files/427_old_db");        
    TEST_ASSERT(file_bytes_equal("test_files/450_good_gpgagent_conf_2", (temp_test_home + "/.gnupg/gpg-agent.conf").c_str()));    
}

void GPGConfFixTests::check_conf_fix_broken_agent_conf_old_db_3() {
    set_full_env(NULL, "test_files/450_bad_gpgagent_conf_3", "test_files/427_old_db");    
    TEST_ASSERT(file_bytes_equal("test_files/450_good_gpgagent_conf_3", (temp_test_home + "/.gnupg/gpg-agent.conf").c_str()));    
}

void GPGConfFixTests::check_conf_fix_broken_agent_conf_old_db_4() {
    set_full_env(NULL, "test_files/450_bad_gpgagent_conf_4", "test_files/427_old_db");        
    TEST_ASSERT(file_bytes_equal("test_files/450_good_gpgagent_conf_4", (temp_test_home + "/.gnupg/gpg-agent.conf").c_str()));    
}

void GPGConfFixTests::check_conf_fix_broken_agent_conf_old_db_5() {
    set_full_env(NULL, "test_files/450_bad_gpgagent_conf_5", "test_files/427_old_db");        
    TEST_ASSERT(file_bytes_equal("test_files/450_good_gpgagent_conf_5", (temp_test_home + "/.gnupg/gpg-agent.conf").c_str()));    
}

void GPGConfFixTests::check_conf_fix_broken_agent_conf_old_db_6() {
    set_full_env(NULL, "test_files/450_bad_gpgagent_conf_6", "test_files/427_old_db");        
    TEST_ASSERT(file_bytes_equal("test_files/450_good_gpgagent_conf_6", (temp_test_home + "/.gnupg/gpg-agent.conf").c_str()));    
}
