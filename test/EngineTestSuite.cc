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
    // but it needn't remain so forever and always.
    prev_gpg_home = getenv("GNUPGHOME");
}

void EngineTestSuite::set_full_env() {

    if (test_home.empty())
        throw "SETUP: BAD INITIALISATION. No test home.";
    
    int success = system("gpgconf --kill all");
    if (success != 0)
        throw "SETUP: Error when executing 'gpgconf --kill all'.";
    
    string home = getenv("HOME");
    if (test_home.compare(home) == 0 || test_home.compare(home + "/") == 0 ||
        test_home.compare(home + "/.gnupg") == 0 || test_home.compare(home + ".gnupg") == 0 ||
        test_home.compare(prev_gpg_home) == 0 || test_home.compare(prev_gpg_home + "/.gnupg") == 0 ||
        test_home.compare(prev_gpg_home + ".gnupg") == 0)
        throw "SETUP: new GNUPGHOME threatens to mess up user GNUPGHOME (and delete all their keys). NO DICE.";
    
    cout << "Ok - checked if new test home will be safe. We'll try and make the directory, deleting it if it has already exists." << endl;
    
    struct stat buf;
    if (stat(test_home.c_str(), &buf) == 0) {
        cout << test_home << " exists. We'll recursively delete. We hope we're not horking your whole system..." << endl;
        success = nftw(test_home.c_str(), util_delete_filepath, 100, FTW_DEPTH);
        if (success != 0)
            throw "SETUP: can't delete the whole directory.";
    }
    
    success = setenv("GNUPGHOME", (test_home + "/.gnupg").c_str(), 1);
    if (success != 0)
        throw "SETUP: Error when setting GNUPGHOME.";

    success = setenv("HOME", test_home.c_str(), 1);
    if (success != 0)
        throw "SETUP: Cannot set test_home for init.";
    
    cout << "calling init()\n";
    PEP_STATUS status = init(&session);
    // assert(status == PEP_STATUS_OK);
    // assert(session);
    cout << "init() completed.\n";

    success = setenv("HOME", home.c_str(), 1);
    if (success != 0)
        throw "SETUP: Cannot reset home directory! Either set environment variable manually back to your home, or quit this session!";    
}

void EngineTestSuite::restore_full_env() {
    int success = system("gpgconf --kill all");
    if (success != 0)
        throw "RESTORE: Error when executing 'gpgconf --kill all'.";

    success = setenv("GNUPGHOME", prev_gpg_home.c_str(), 1);
    if (success != 0)
        throw "RESTORE: Warning - cannot restore GNUPGHOME. Either set environment variable manually back to your home, or quit this session!";
}

int EngineTestSuite::util_delete_filepath(const char *filepath, 
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

void EngineTestSuite::setup() {}
void EngineTestSuite::tear_down() {}
