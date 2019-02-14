#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <ftw.h>
#include <assert.h>
#include <fstream>
#include <iostream>
#include <sys/types.h>
#include <dirent.h>

#include <string>
#include <vector>
#include <utility>

#include "platform_unix.h"

#include "TestUtils.h"
#include "pEpTestDevice.h"
#include "pEpTestStatic.h"
#include <algorithm>
#include "TestConstants.h"
#include <chrono>

pEpTestDevice::pEpTestDevice(string test_dir, 
                             string my_name,
                             messageToSend_t mess_send_func,
                             inject_sync_event_t inject_sync_ev_func
                             )                
{
    root_test_dir = test_dir;
    // FIXME: do we have to worry about dirlen now?
    device_dir = test_dir + "/" + my_name;
    device_name = my_name;
    device_messageToSend = mess_send_func;
    device_inject_sync_event = inject_sync_ev_func;
    
    set_device_environment();    
}

pEpTestDevice::~pEpTestDevice() {
    unset_device_environment();
    // FIXME: Remove homedir
    nftw((device_dir).c_str(), util_delete_filepath, 100, FTW_DEPTH);
}

void pEpTestDevice::set_device_environment() {
    int success = 0;
    struct stat dirchk;
    
//    set_my_name();

// FIXME
#ifndef USE_NETPGP
    success = system("gpgconf --kill all");
    if (success != 0)
        throw std::runtime_error("SETUP: Error when executing 'gpgconf --kill all'.");    
#endif

    if (stat(device_dir.c_str(), &dirchk) == 0) {
        if (!S_ISDIR(dirchk.st_mode))
            throw std::runtime_error(("The test directory, " + device_dir + "exists, but is not a directory.").c_str()); 
                    
        struct stat buf;

        if (stat(device_dir.c_str(), &buf) == 0) {
            int success = nftw((device_dir + "/.").c_str(), util_delete_filepath, 100, FTW_DEPTH);
        }
    }
    else {
        int errchk = mkdir(device_dir.c_str(), S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
        cout << errchk << endl;
        if (errchk != 0)
            throw std::runtime_error("Error creating a test directory.");
    }
        
    struct stat buf;
        
    success = setenv("GNUPGHOME", (device_dir + "/gnupg").c_str(), 1);

    if (success != 0)
        throw std::runtime_error("SETUP: Error when setting GNUPGHOME.");

    cout << "New GNUPGHOME is " << getenv("GNUPGHOME") << endl << endl;
        
    success = setenv("HOME", device_dir.c_str(), 1);
    if (success != 0)
        throw std::runtime_error("SETUP: Cannot set copy_fil for init.");
            
    unix_local_db(true);
    gpg_conf(true);
    gpg_agent_conf(true);
        
    PEP_STATUS status = init(&session, device_messageToSend, device_inject_sync_event);

#ifndef USE_NETPGP            
    success = system("gpgconf --create-socketdir");
    if (success != 0)
        throw std::runtime_error("RESTORE: Error when executing 'gpgconf --create-socketdir'.");        
    system("gpg-connect-agent /bye");   // Just in case - otherwise, we die on MacOS sometimes. Is this enough??
#endif

    assert(status == PEP_STATUS_OK);
    assert(session);
}

void pEpTestDevice::grab_context(pEpTestDevice* victim) {
    victim->unset_device_environment();
    set_device_environment();
// 
//     int success = system("gpgconf --kill all");
//     if (success != 0)
//         throw std::runtime_error("SETUP: Error when executing 'gpgconf --kill all'.");    
//     struct stat buf;
// 
//     success = system("gpgconf --remove-socketdir");            
//     if (success != 0)
//         throw std::runtime_error("RESTORE: Error when executing 'gpgconf --remove-socketdir'.");    
// 
//     success = setenv("GNUPGHOME", (device_dir + "/gnupg").c_str(), 1);
// 
//     if (success != 0)
//         throw std::runtime_error("SETUP: Error when setting GNUPGHOME.");
// 
//     cout << "New GNUPGHOME is " << getenv("GNUPGHOME") << endl << endl;
// 
//     success = setenv("HOME", device_dir.c_str(), 1);
//     if (success != 0)
//         throw std::runtime_error("SETUP: Cannot set device_dir for init.");
// 
// w#ifndef USE_NETPGP            
//     success = system("gpgconf --create-socketdir");
//     if (success != 0)
//         throw std::runtime_error("RESTORE: Error when executing 'gpgconf --create-socketdir'.");        
//     system("gpg-connect-agent /bye");   // Just in case - otherwise, we die on MacOS sometimes. Is this enough??
// #endif
}

void pEpTestDevice::unset_device_environment() {
    if (session)
        release(session);
    session = NULL;
        
    int success = 0;    

#ifndef USE_NETPGP        
    success = system("gpgconf --kill all");
    if (success != 0)
        throw std::runtime_error("RESTORE: Error when executing 'gpgconf --kill all'.");
    success = system("gpgconf --remove-socketdir");            
    if (success != 0)
        throw std::runtime_error("RESTORE: Error when executing 'gpgconf --remove-socketdir'.");    
#endif

    unix_local_db(true);
    gpg_conf(true);
    gpg_agent_conf(true);
}

void pEpTestDevice::set_mailbox_dir(string mbox_dirname) {
    mbox_dir = mbox_dirname;
    struct stat dirchk;
    
    if (stat(mbox_dir.c_str(), &dirchk) == 0) {
        if (!S_ISDIR(dirchk.st_mode))
            throw std::runtime_error(("The mbox directory, " + device_dir + "exists, but is not a directory.").c_str());                     
    }
    else {
        int errchk = mkdir(mbox_dir.c_str(), S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
        cout << errchk << endl;
        if (errchk != 0)
            throw std::runtime_error("Error creating an mbox directory.");
    }    
}

string pEpTestDevice::save_mail_to_mailbox(string mail) {
    if (mail.empty())
        throw std::runtime_error("Attempt to write empty mail to mailbox.");

    struct stat dirchk;
    
    if (mbox_dir.empty() || stat(mbox_dir.c_str(), &dirchk) == 0)
        throw std::runtime_error("pEpTestDevice: mailbox dir not initialised or removed.");                     

    chrono::milliseconds timestamp = chrono::duration_cast< chrono::milliseconds >(
                                        chrono::system_clock::now().time_since_epoch());
    
    string outfile_name = mbox_dir + "/" + to_string(timestamp.count()) + ".eml";

    ofstream outfile;
    
    outfile.open(outfile_name);
    outfile << mail;
    outfile.close();    
    return outfile_name;
}

// Presumes everything in mbox dir is a .eml file
// and was written in above ts form. We can change later if needed.
vector<string> pEpTestDevice::check_mail() {
    mail_to_read.clear();
    struct stat dirchk;

    if (mbox_dir.empty() || stat(mbox_dir.c_str(), &dirchk) == 0)
        throw std::runtime_error("pEpTestDevice: mailbox dir not initialised or removed.");                     

    vector<string> email_list;
    DIR* dir;   
    dirent* pdir;
 
    dir = opendir(mbox_dir.c_str()); 
    while ((pdir = readdir(dir)))
        email_list.push_back(pdir->d_name);  

    if (email_list.empty())
        return email_list;
    else    
        sort(email_list.begin(), email_list.end());
    
    if (mbox_last_read.empty())
        return email_list;
    
    string last_read_time_str = 
        mbox_last_read.substr(0, mbox_last_read.find_last_of("."));
    unsigned long long last_read_ts = strtoull(last_read_time_str.c_str(), NULL, 10);
    
    int i = 0;
    
    for (vector<string>::iterator it = email_list.begin();
         it != email_list.end(); it++, i++) {
        string fname = *it;
        if (fname.empty())
            continue; // ??

        // I don't want to think about how to format to do a strcmp atm
        size_t dot_pos = fname.find_last_of(".");
        string ts_str = fname.substr(0, dot_pos);
        
        unsigned long long file_ts = strtoull(ts_str.c_str(), NULL, 10);
        
        if (file_ts > last_read_ts)
            break;
    }
    
    if (i > email_list.size())
        email_list.clear();
    else {
        if (i != 0) {
            vector<string> not_read(email_list.begin() + i, email_list.end());
            email_list = not_read;
        }
    }     
    
    return email_list;
}
