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
#include "mime.h"
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
    victim->process_send_queue();
    victim->unset_device_environment();
    set_device_environment();
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

string pEpTestDevice::receive_mail(string mail) {
    return save_mail_to_mailbox(mbox_dir, mail);
}

PEP_STATUS pEpTestDevice::send_mail(message* mail) {
    if (!mail->to)
        return PEP_ILLEGAL_VALUE;
        
    identity_list* to_list = mail->to;
    if (!to_list)
        return PEP_ILLEGAL_VALUE;

    char* msg_str = NULL;
    PEP_STATUS status = mime_encode_message(mail, false, &msg_str);
    if (status != PEP_STATUS_OK)
        return status;
    if (!msg_str)
        return PEP_UNKNOWN_ERROR;
    
    for (identity_list* tl_curr = to_list; tl_curr; tl_curr = tl_curr->next) {
        if (!tl_curr->ident)
            return PEP_ILLEGAL_VALUE;
        const char* to = tl_curr->ident->address;
        if (!to || to[0] == '\0')
            return PEP_ILLEGAL_VALUE;
            
        std::map<string,string>::iterator it = address_to_mbox_map.find(to);
        if (it == address_to_mbox_map.end() || it->second.empty())
            return PEP_RECORD_NOT_FOUND;
        string mbox = it->second;
        if (save_mail_to_mailbox(mbox, msg_str).empty())
            return PEP_CANNOT_CREATE_TEMP_FILE;
    }    
    return PEP_STATUS_OK;
}

PEP_STATUS pEpTestDevice::process_send_queue() {
    for (vector<message*>::iterator it = send_queue.begin(); it != send_queue.end(); it++) {
        if (!*it) {
            PEP_STATUS status = send_mail(*it);
            if (status != PEP_STATUS_OK)
                return status;
        }
    }
    send_queue.clear();
    return PEP_STATUS_OK;
}

string pEpTestDevice::save_mail_to_mailbox(string mailbox_path, string mail) {
    if (mail.empty())
        throw std::runtime_error("Attempt to write empty mail to mailbox.");

    struct stat dirchk;
    
    if (mailbox_path.empty() || stat(mailbox_path.c_str(), &dirchk) != 0)
        throw std::runtime_error("pEpTestDevice: mailbox dir not initialised or removed.");                     

    chrono::milliseconds timestamp = chrono::duration_cast< chrono::milliseconds >(
                                        chrono::system_clock::now().time_since_epoch());
    
    string outfile_name = mailbox_path + "/" + to_string(timestamp.count()) + ".eml";

    ofstream outfile;
    
    outfile.open(outfile_name);
    outfile << mail;
    outfile.flush();
    outfile.close(); 
    cout << "Wrote " + outfile_name << endl;
    usleep(1000); // guarantees change in filename
    return outfile_name;
}

// Presumes everything in mbox dir is a .eml file
// and was written in above ts form. We can change later if needed.
void pEpTestDevice::check_mail(vector<string> &unread) {
    unread.clear();
    mail_to_read.clear();
    struct stat dirchk;

    if (mbox_dir.empty() || stat(mbox_dir.c_str(), &dirchk) != 0)
        throw std::runtime_error("pEpTestDevice: mailbox dir not initialised or removed.");                     

    DIR* dir;   
    dirent* pdir;
 
    dir = opendir(mbox_dir.c_str()); 
    while ((pdir = readdir(dir))) {
        struct stat dirchk2;
        const char* fname = pdir->d_name;
        if (strcmp(fname, ".") && strcmp(fname, "..")) {
            stat((mbox_dir + fname).c_str(), &dirchk2);
            cout << "I see " << fname << endl;
            if (!S_ISDIR(dirchk2.st_mode)) {
                unread.push_back(fname); 
                cout << "I pushed " << fname << endl; 
            }    
        }        
    }    

    if (unread.empty())
        return;
    else    
        sort(unread.begin(), unread.end());
    
    if (!mbox_last_read.empty()) {
    
        string last_read_time_str = 
            mbox_last_read.substr(0, mbox_last_read.find_last_of("."));
        unsigned long long last_read_ts = strtoull(last_read_time_str.c_str(), NULL, 10);
        
        int i = 0;
        
        for (vector<string>::iterator it = unread.begin();
             it != unread.end(); it++, i++) {
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
        
        if (i > unread.size())
            unread.clear();
        else {
            if (i != 0) {
                unread.erase(unread.begin(), unread.begin() + i);
                cout << "Unread contains: " << endl;
                for (vector<string>::iterator it = unread.begin();
                     it != unread.end(); it++) {
                    cout << *it << endl;
                }
            }
        }     
    }
    
    mbox_last_read = string(unread.back());    
}

void pEpTestDevice::read_mail(vector<string> mails, vector<string> &to_read) {
    to_read.clear();
    for (vector<string>::iterator it = mails.begin();
         it != mails.end(); it++) {
        string mail = slurp(mbox_dir + "/" + *it);
        if (mail.empty())
            continue;
        to_read.push_back(mail);
    }
}
