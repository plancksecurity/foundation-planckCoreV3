#ifndef PEP_TEST_DEVICE_H
#define PEP_TEST_DEVICE_H

#include <cpptest.h>
#include <string>
#include <map>
#include <vector>
#include <utility>
#include "pEpEngine.h"
#include "message.h"
#include "sync_api.h"
#include "locked_queue.hh"
#include "Sync_event.h"

using namespace std;

class pEpTestDevice {
    public:
        pEpTestDevice(string test_dir, string my_name);        
                      
        virtual ~pEpTestDevice();
        
        static pEpTestDevice* active;
        static void switch_context(pEpTestDevice* switch_to);

        // Write mail string to a timestamp-named file in the listed mailbox,
        // and return the name of the file.
        static string save_mail_to_mailbox(string mailbox_path, string mail);

        void set_mailbox_dir(string mbox_dirname);
        
        // set my variables as the environment vars (HOME, GNUPGHOME, etc)
        void set_device_environment();
        
        // clean up crypto agents and 
        void unset_device_environment();
        
        // Make all of this device's environment information the current
        // environment, and restart session for this device with this,
        // releasing the victim's device and session (and processing their 
        // send queue before doing this)
        void grab_context(pEpTestDevice* victim);

        // take string and save to own mailbox as timestamped mail file and 
        // return filename 
        string receive_mail(string mail); 
        
        // Get the filenames of all unread mails
        void check_mail(vector<string> &unread);
        
        // Read all mails (by filename) into a vector of strings
        void read_mail(vector<string>mails, vector<message*> &to_read);
        
        // write everything into the correct mail by mailbox.
        // PRESUMES address_to_mbox_map HAS AN ENTRY FOR EVERY ADDRESS IN 
        // THE RECIP LIST
        PEP_STATUS process_send_queue();
        
        // write individual message struct to the correct mailbox
        PEP_STATUS send_mail(message* mail);

        void add_message_to_send_queue(message* msg);
        
        string device_name;
        PEP_SESSION session;
        string device_dir;        
        string root_test_dir;
        string mbox_dir;
        utility::locked_queue<Sync_event_t*> q;

        static Sync_event_t* retrieve_next_sync_event(void *management, time_t threshold);
        static int notify_handshake(pEp_identity *me,
                                    pEp_identity *partner,
                                    sync_handshake_signal signal);
        
        static int inject_sync_event(SYNC_EVENT ev, void *management);
//        Sync_event_t *retrieve_next_sync_event(void *management, unsigned threshold);
        static PEP_STATUS message_to_send(struct _message *msg);


//        messageToSend_t device_messageToSend;
//        inject_sync_event_t device_inject_sync_event;
        map<string,string> address_to_mbox_map; // maybe string, vector<string>?
        
    protected:        
        string mbox_last_read;
        vector<string> mail_to_read;
        vector<message*> send_queue;
        
//        string current_test_name;
        
//        void set_full_env();
//        void set_full_env(const char* gpg_conf_copy_path, const char* gpg_agent_conf_file_copy_path, const char* db_conf_file_copy_path);
//        void restore_full_env();
//        void initialise_test_home();
	
        // std::vector<std::pair<std::string, std::string>> gpgdir_fileadd_queue;
        // std::vector<std::pair<std::string, std::string>> homedir_fileadd_queue;
        // void add_file_to_gpg_dir_queue(std::string copy_from, std::string dst_fname);    
        // void add_file_to_home_dir_queue(std::string copy_from, std::string dst_fname);
        // void process_file_queue(std::string dirname, std::vector<std::pair<std::string, std::string>> file_queue);
};
    
#endif
