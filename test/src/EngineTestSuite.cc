#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <ftw.h>
#include <assert.h>
#include <fstream>
#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>

#include "platform_unix.h"

#include "test_util.h"
#include "EngineTestSuite.h"
using namespace std;

// Constructor
EngineTestSuite::EngineTestSuite(string suitename, string test_home_dir) {
    // FIXME: deal with base
    test_home = test_home_dir;
            
    number_of_tests = 0;
    on_test_number = 0;
    real_home = getenv("HOME");
}

EngineTestSuite::~EngineTestSuite() {}

void EngineTestSuite::add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()> test_func) {
    test_map.insert(test_func);
    register_test(test_func.second, test_func.first);
    number_of_tests++;
}

void EngineTestSuite::copy_conf_file_to_test_dir(const char* dest_path, const char* conf_orig_path, const char* conf_dest_name) {
    string conf_dest_path = dest_path;
    
    struct stat pathinfo;

    if(stat(conf_dest_path.c_str(), &pathinfo) != 0) {
        int errchk = mkdir(conf_dest_path.c_str(), S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
        if (errchk != 0)
            throw std::runtime_error("Error accessing conf file directory.");
    }
    
    conf_dest_path += "/";
    conf_dest_path += conf_dest_name;
    
    ifstream src(conf_orig_path);
    ofstream dst(conf_dest_path.c_str(), ios::trunc);
    
    assert(src);
    assert(dst);
    
    dst << src.rdbuf();
     
    src.close();
    dst.close();
}

void EngineTestSuite::set_full_env() {
    set_full_env(NULL, NULL, NULL);
}

void EngineTestSuite::set_full_env(const char* gpg_conf_copy_path, const char* gpg_agent_conf_file_copy_path, const char* db_conf_file_copy_path) {
    int success = 0;
    struct stat dirchk;
    
    set_my_name();

    success = system("gpgconf --kill all");
    if (success != 0)
        throw std::runtime_error("SETUP: Error when executing 'gpgconf --kill all'.");
 //   sleep(1); // hopefully enough time for the system to recognise that it is dead. *sigh*    

    if (stat(test_home.c_str(), &dirchk) == 0) {
        if (!S_ISDIR(dirchk.st_mode))
            throw std::runtime_error(("The test directory, " + test_home + "exists, but is not a directory.").c_str()); 
                    
        struct stat buf;

        if (stat(test_home.c_str(), &buf) == 0) {
            cout << test_home << " exists. We'll recursively delete. We hope we're not horking your whole system..." << endl;
            int success = nftw((test_home + "/.").c_str(), util_delete_filepath, 100, FTW_DEPTH);
        }
    }
    else {
        int errchk = mkdir(test_home.c_str(), S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
        cout << errchk << endl;
        if (errchk != 0)
            throw std::runtime_error("Error creating a test directory.");
    }

    temp_test_home = test_home + "/" + my_name;
    
    int errchk = mkdir(temp_test_home.c_str(), S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
    if (errchk != 0)
        throw std::runtime_error("Error creating a test directory.");

    temp_test_home += "/" + to_string(on_test_number);

    errchk = mkdir(temp_test_home.c_str(), S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
    if (errchk != 0)
        throw std::runtime_error("Error creating a test directory.");

    // TODO: This is *nix specific, which the current testing env is anyway,
    // but it needn't remain so forever and always
    char* tmp = getenv("GNUPGHOME");
    if (tmp)
        prev_gpg_home = tmp;
        
    if (temp_test_home.empty())
        throw std::runtime_error("SETUP: BAD INITIALISATION. No test home.");

    
    string home = getenv("HOME");
    cout << "home is " << home << endl;
    assert(temp_test_home.compare(home) != 0);
    assert(temp_test_home.compare(home + "/") != 0);
    assert(temp_test_home.compare(home + "") != 0);
    assert(temp_test_home.compare(home + ".gnupg") != 0);
    assert(temp_test_home.compare(prev_gpg_home) != 0);
    assert(temp_test_home.compare(prev_gpg_home + "/.gnupg") != 0);
    assert(temp_test_home.compare(prev_gpg_home + ".gnupg") != 0);

    if (temp_test_home.compare(home) == 0 || temp_test_home.compare(home + "/") == 0 ||
        temp_test_home.compare(home + "/.gnupg") == 0 || temp_test_home.compare(home + ".gnupg") == 0 ||
        temp_test_home.compare(prev_gpg_home) == 0 || temp_test_home.compare(prev_gpg_home + "/.gnupg") == 0 ||
        temp_test_home.compare(prev_gpg_home + ".gnupg") == 0)
        throw std::runtime_error("SETUP: new GNUPGHOME threatens to mess up user GNUPGHOME (and delete all their keys). NO DICE.");
    
//    cout << "Ok - checked if new test home will be safe. We'll try and make the directory, deleting it if it has already exists." << endl;
    
    struct stat buf;
    
    success = setenv("GNUPGHOME", (temp_test_home + "/.gnupg").c_str(), 1);
    if (success != 0)
        throw std::runtime_error("SETUP: Error when setting GNUPGHOME.");

    cout << "New GNUPGHOME is " << getenv("GNUPGHOME") << endl;
    
    success = setenv("HOME", temp_test_home.c_str(), 1);
    if (success != 0)
        throw std::runtime_error("SETUP: Cannot set test_home for init.");

    if (gpg_conf_copy_path)
        copy_conf_file_to_test_dir((temp_test_home + "/.gnupg").c_str(), gpg_conf_copy_path, "gpg.conf");
    if (gpg_agent_conf_file_copy_path)        
        copy_conf_file_to_test_dir((temp_test_home + "/.gnupg").c_str(), gpg_agent_conf_file_copy_path, "gpg-agent.conf");
    if (db_conf_file_copy_path)
        copy_conf_file_to_test_dir(temp_test_home.c_str(), db_conf_file_copy_path, ".pEp_management.db");
        
    unix_local_db(true);
    gpg_conf(true);
    gpg_agent_conf(true);
    
//    cout << "calling init()\n";
    PEP_STATUS status = init(&session);
    assert(status == PEP_STATUS_OK);
    assert(session);
//    cout << "init() completed.\n";

}

void EngineTestSuite::restore_full_env() {
    release(session);
    session = NULL;
        
    int success = system("gpgconf --kill all");
    if (success != 0)
        throw std::runtime_error("RESTORE: Error when executing 'gpgconf --kill all'.");

    success = setenv("GNUPGHOME", prev_gpg_home.c_str(), 1);
    if (success != 0)
        throw std::runtime_error("RESTORE: Warning - cannot restore GNUPGHOME. Either set environment variable manually back to your home, or quit this session!");
                
    success = nftw((test_home + "/.").c_str(), util_delete_filepath, 100, FTW_DEPTH);
    
    success = setenv("HOME", real_home.c_str(), 1);
    if (success != 0)
        throw std::runtime_error("RESTORE: Cannot reset home directory! Either set environment variable manually back to your home, or quit this session!");
    else
        cout << "RESTORE: HOME is now " << getenv("HOME") << endl;
    unix_local_db(true);
    gpg_conf(true);
    gpg_agent_conf(true);

}

void EngineTestSuite::setup() {
    on_test_number++;
}

void EngineTestSuite::tear_down() {}

void EngineTestSuite::set_my_name() {
    my_name = typeid(*this).name();
}
