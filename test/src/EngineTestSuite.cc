#include <stdlib.h>
#include <unistd.h>
#include <ftw.h>

#include "EngineTestSuite.h"
using namespace std;

// Constructor
EngineTestSuite::EngineTestSuite(string suitename, string test_home_dir) {
    // FIXME: deal with base
    test_home = test_home_dir;
    
    // TODO: This is *nix specific, which the current testing env is anyway,
    // but it needn't remain so forever and always
    char* tmp = getenv("GNUPGHOME");
    if (tmp)
        prev_gpg_home = getenv("GNUPGHOME");
        
    number_of_tests = 0;
    on_test_number = 0;
}

EngineTestSuite::~EngineTestSuite() {}

void EngineTestSuite::add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()> test_func) {
    test_map.insert(test_func);
    register_test(test_func.second, test_func.first);
    number_of_tests++;
}

void EngineTestSuite::set_full_env() {

    if (test_home.empty())
        throw std::runtime_error("SETUP: BAD INITIALISATION. No test home.");
    
    int success = system("gpgconf --kill all");
    if (success != 0)
        throw std::runtime_error("SETUP: Error when executing 'gpgconf --kill all'.");
    
    string home = getenv("HOME");
    if (test_home.compare(home) == 0 || test_home.compare(home + "/") == 0 ||
        test_home.compare(home + "/.gnupg") == 0 || test_home.compare(home + ".gnupg") == 0 ||
        test_home.compare(prev_gpg_home) == 0 || test_home.compare(prev_gpg_home + "/.gnupg") == 0 ||
        test_home.compare(prev_gpg_home + ".gnupg") == 0)
        throw std::runtime_error("SETUP: new GNUPGHOME threatens to mess up user GNUPGHOME (and delete all their keys). NO DICE.");
    
//    cout << "Ok - checked if new test home will be safe. We'll try and make the directory, deleting it if it has already exists." << endl;
    
    struct stat buf;
    
    success = setenv("GNUPGHOME", (test_home + "/.gnupg").c_str(), 1);
    if (success != 0)
        throw std::runtime_error("SETUP: Error when setting GNUPGHOME.");

    success = setenv("HOME", test_home.c_str(), 1);
    if (success != 0)
        throw std::runtime_error("SETUP: Cannot set test_home for init.");
    
//    cout << "calling init()\n";
    PEP_STATUS status = init(&session);
    // assert(status == PEP_STATUS_OK);
    // assert(session);
//    cout << "init() completed.\n";

    success = setenv("HOME", home.c_str(), 1);
    if (success != 0)
        throw std::runtime_error("SETUP: Cannot reset home directory! Either set environment variable manually back to your home, or quit this session!");    
}

void EngineTestSuite::restore_full_env() {
    int success = system("gpgconf --kill all");
    if (success != 0)
        throw std::runtime_error("RESTORE: Error when executing 'gpgconf --kill all'.");

    success = setenv("GNUPGHOME", prev_gpg_home.c_str(), 1);
    if (success != 0)
        throw std::runtime_error("RESTORE: Warning - cannot restore GNUPGHOME. Either set environment variable manually back to your home, or quit this session!");
}

void EngineTestSuite::setup() {
    on_test_number++;
}

void EngineTestSuite::tear_down() {}
