#include <stdlib.h>
#include <string.h>
#include "platform.h"
#include <iostream>
#include <fstream>
#include <assert.h>
#include "mime.h"
#include "message_api.h"

using namespace std;


int main(int argc, char** argv) {
    
        const char* filename = "test_mails/memoryhole_B.eml";
        
        PEP_SESSION session;

        cout << "calling init()\n";
        PEP_STATUS status1 = init(&session);
        assert(status1 == PEP_STATUS_OK);
        assert(session);
        cout << "init() completed.\n";

        // message_api test code

        // pEp_identity * me2 = new_identity("pep.test.alice@pep-project.org", NULL, PEP_OWN_USERID, "Alice Test");
        // pEp_identity * me2 = new_identity("test@nokey.plop", NULL, PEP_OWN_USERID, "Test no key");

        // FIXME: Ugh. Maybe identities have to be args. But this is a kludge.
        pEp_identity* me2 = new_identity("krista@kgrothoff.org", "62D4932086185C15917B72D30571AFBCA5493553", PEP_OWN_USERID, "Krista Grothoff");
        me2->me = true;

        ifstream inFile3(filename);
        assert(inFile3.is_open());

        string text3;

        while (!inFile3.eof()) {
            static string line;
            getline(inFile3, line);
            text3 += line + "\r\n";
        }
        inFile3.close();

        message* msg;
        const char* text3_str = text3.c_str();

        //cout << text3.c_str();
//        parse_mailmessage(text3_str, &msg);
        
         message *msg5 = nullptr;
         PEP_STATUS status5 = mime_decode_message(text3.c_str(), text3.length(), &msg5);
         assert(status5 == PEP_STATUS_OK);
//         //    cout << msg5->longmsg;
// 
//             message *msg6 = nullptr;
//             stringlist_t *keylist5 = nullptr;
//             PEP_color color2;
//             PEP_decrypt_flags_t flags2;
//             PEP_STATUS status6 = decrypt_message(session, msg5, &msg6, &keylist5, &color2, &flags2);
        //     assert(status6 == PEP_DECRYPT_NO_KEY);
        //     assert(msg6 == NULL);
        //     assert(keylist5 == NULL);
        //     assert(color2 == PEP_rating_have_no_key);
        //     cout << "color :" << color2 << "\n";
        //     free_stringlist(keylist5);
        // 
        //     cout << "freeing messages…\n";
        //     free_message(msg4);
        //     free_message(msg3);
        //     free_message(msg2);
        //     free_message(enc_msg2);
        //     free_message(msg6);
        //     free_message(msg5);
        //     cout << "done.\n";
        cout << "calling release()\n";
        release(session);
    //}
    return 0;
}
