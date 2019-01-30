// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef KEY_ATTACHMENT_H
#define KEY_ATTACHMENT_H

#include <string>
#include "EngineTestIndividualSuite.h"

using namespace std;

class KeyAttachmentTests : public EngineTestIndividualSuite {
    public:
        KeyAttachmentTests(string test_suite, string test_home_dir);
    protected:
        void setup();        
    private:
        void check_key_attachment();
        void check_key_attach_inline();
        void check_key_plus_encr_att_inline();
        void check_encr_att_plus_key_inline();
        void check_key_plus_unencr_att_inline(); // not really unencrypted; just not encrypted before attachment
        void check_unencr_att_plus_key_inline(); // not really unencrypted; just not encrypted before attachment
        void check_many_keys_inline();        
        void check_many_keys_w_encr_file_inline();        
        void check_many_keys_w_unencr_file_inline(); // not really unencrypted; just not encrypted before attachment
        void check_key_attach_OpenPGP();
        void check_key_plus_encr_att_OpenPGP();
        void check_encr_att_plus_key_OpenPGP();
        void check_key_plus_unencr_att_OpenPGP(); 
        void check_unencr_att_plus_key_OpenPGP(); 
        void check_many_keys_OpenPGP();        
        void check_many_keys_w_encr_file_OpenPGP();        
        void check_many_keys_w_unencr_file_OpenPGP();         
        void check_many_keys_w_many_files_OpenPGP();
};

#endif
