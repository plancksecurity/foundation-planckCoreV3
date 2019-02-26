// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include "TestConstants.h"
#include <string>
#include <cstring>
#include <iostream>
#include <fstream>

#include "pEpEngine.h"
#include "platform.h"
#include "mime.h"
#include "message_api.h"
#include "TestUtils.h"

#include <cpptest.h>
#include "EngineTestSessionSuite.h"
#include "MessageApiTests.h"

using namespace std;

MessageApiTests::MessageApiTests(string suitename, string test_home_dir) :
    EngineTestSessionSuite::EngineTestSessionSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("MessageApiTests::check_message_api"),
                                                                      static_cast<Func>(&MessageApiTests::check_message_api)));
}

void MessageApiTests::check_message_api() {
    cout << "Importing Alice's key " << endl;
    const string alice_pub_key = slurp("test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    const string alice_priv_key = slurp("test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc");
    const string bob_pub_key = slurp("test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc");

    PEP_STATUS status0 = import_key(session, alice_pub_key.c_str(), alice_pub_key.size(), NULL);
    TEST_ASSERT_MSG((status0 == PEP_TEST_KEY_IMPORT_SUCCESS), "status0 == PEP_STATUS_OK");
    status0 = import_key(session, alice_priv_key.c_str(), alice_priv_key.size(), NULL);
    TEST_ASSERT_MSG((status0 == PEP_TEST_KEY_IMPORT_SUCCESS), "status0 == PEP_STATUS_OK");
    status0 = import_key(session, bob_pub_key.c_str(), bob_pub_key.size(), NULL);
    TEST_ASSERT_MSG((status0 == PEP_TEST_KEY_IMPORT_SUCCESS), "status0 == PEP_STATUS_OK");
    // message_api test code

    cout << "creating message…\n";
    pEp_identity * me2 = new_identity("pep.test.alice@pep-project.org", NULL, PEP_OWN_USERID, "Alice Test");
    // pEp_identity * me2 = new_identity("test@nokey.plop", NULL, PEP_OWN_USERID, "Test no key");
    me2->me = true;
    identity_list *to2 = new_identity_list(new_identity("pep.test.bob@pep-project.org", NULL, "42", "Bob Test"));
    // identity_list *to2 = new_identity_list(new_identity("still@nokey.blup", NULL, "42", "Still no key"));
    message *msg2 = new_message(PEP_dir_outgoing);
    TEST_ASSERT_MSG((msg2), "msg2");
    msg2->from = me2;
    msg2->to = to2;
    msg2->shortmsg = strdup("hello, world");
    msg2->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);
    cout << "message created.\n";

    char *text2 = nullptr;
    PEP_STATUS status2 = mime_encode_message(msg2, false, &text2);
    TEST_ASSERT_MSG((status2 == PEP_STATUS_OK), "status2 == PEP_STATUS_OK");
    TEST_ASSERT_MSG((text2), "text2");

    cout << "decrypted:\n\n";
    cout << text2 << "\n";

    free(text2);

    cout << "encrypting message as MIME multipart…\n";
    message *enc_msg2 = nullptr;
    cout << "calling encrypt_message()\n";
    status2 = encrypt_message(session, msg2, NULL, &enc_msg2, PEP_enc_PGP_MIME, 0);
    cout << "encrypt_message() returns " << status2 << '.' << endl;
    TEST_ASSERT_MSG((status2 == PEP_STATUS_OK), "status2 == PEP_STATUS_OK");
    TEST_ASSERT_MSG((enc_msg2), "enc_msg2");
    cout << "message encrypted.\n";
    
    status2 = mime_encode_message(enc_msg2, false, &text2);
    TEST_ASSERT_MSG((status2 == PEP_STATUS_OK), "status2 == PEP_STATUS_OK");
    TEST_ASSERT_MSG((text2), "text2");

    cout << "encrypted:\n\n";
    cout << text2 << "\n";

    message *msg3 = nullptr;
    PEP_STATUS status3 = mime_decode_message(text2, strlen(text2), &msg3);
    TEST_ASSERT_MSG((status3 == PEP_STATUS_OK), "status3 == PEP_STATUS_OK");
    const string string3 = text2;
    //free(text2);

    unlink("msg4.asc");
    ofstream outFile3("msg4.asc");
    outFile3.write(string3.c_str(), string3.size());
    outFile3.close();

    message *msg4 = nullptr;
    stringlist_t *keylist4 = nullptr;
    PEP_rating rating;
    PEP_decrypt_flags_t flags;
    
    flags = 0;
    PEP_STATUS status4 = decrypt_message(session, enc_msg2, &msg4, &keylist4, &rating, &flags);
    TEST_ASSERT_MSG((status4 == PEP_STATUS_OK), tl_status_string(status4));
    TEST_ASSERT_MSG((msg4), "msg4");
    TEST_ASSERT_MSG((keylist4), "keylist4");
    TEST_ASSERT_MSG((rating), "rating");
    PEP_comm_type ct = enc_msg2->from->comm_type;
    TEST_ASSERT_MSG((ct == PEP_ct_pEp || ct == PEP_ct_pEp_unconfirmed || ct == PEP_ct_OpenPGP || ct == PEP_ct_OpenPGP_unconfirmed ), "ct == PEP_ct_pEp || ct == PEP_ct_pEp_unconfirmed || ct == PEP_ct_OpenPGP || ct == PEP_ct_OpenPGP_unconfirmed ");

    free_stringpair_list(enc_msg2->opt_fields);
    enc_msg2->opt_fields = NULL;

    cout << "keys used:";

    for (stringlist_t* kl4 = keylist4; kl4 && kl4->value; kl4 = kl4->next)
    {
        cout << " " << kl4->value;
    }
    cout << "\n\n";

    free_stringlist(keylist4);

    cout << "opening msg_no_key.asc for reading\n";
    ifstream inFile3 ("msg_no_key.asc");
    TEST_ASSERT_MSG((inFile3.is_open()), "inFile3.is_open()");

    string text3;

    cout << "reading msg_no_key.asc sample\n";
    while (!inFile3.eof()) {
        static string line;
        getline(inFile3, line);
        text3 += line + "\r\n";
    }
    inFile3.close();

    message *msg5 = nullptr;
    PEP_STATUS status5 = mime_decode_message(text3.c_str(), text3.length(), &msg5);
    TEST_ASSERT_MSG((status5 == PEP_STATUS_OK), "status5 == PEP_STATUS_OK");

    message *msg6 = nullptr;
    stringlist_t *keylist5 = nullptr;
    PEP_rating rating2;
    PEP_decrypt_flags_t flags2;
    flags2 = 0;
    PEP_STATUS status6 = decrypt_message(session, msg5, &msg6, &keylist5, &rating2, &flags2);
    TEST_ASSERT_MSG((status6 == PEP_DECRYPT_NO_KEY), tl_status_string(status6));
    TEST_ASSERT_MSG((msg6 == NULL), "msg6 == NULL");
    TEST_ASSERT_MSG((keylist5 == NULL), "keylist5 == NULL");
    TEST_ASSERT_MSG((rating2 == PEP_rating_have_no_key), "rating2 == PEP_rating_have_no_key");
    cout << "rating :" << rating2 << "\n";
    free_stringlist(keylist5);

    cout << "\nTesting MIME_encrypt_message / MIME_decrypt_message...\n\n";

    cout << "opening alice_bob_encrypt_test_plaintext_mime.eml for reading\n";
    ifstream inFile4 ("test_mails/alice_bob_encrypt_test_plaintext_mime.eml");
    TEST_ASSERT_MSG((inFile4.is_open()), "inFile4.is_open()");
    
    string text4;
    
    cout << "reading alice_bob_encrypt_test_plaintext_mime.eml sample\n";
    while (!inFile4.eof()) {
        static string line;
        getline(inFile4, line);
        text4 += line + "\r\n";
    }
    inFile4.close();
    
    const char* out_msg_plain = text4.c_str();
    
//    const char* out_msg_plain = "From: krista@kgrothoff.org\nTo: Volker <vb@pep-project.org>\nSubject: Test\nContent-Type: text/plain; charset=utf-8\nContent-Language: en-US\nContent-Transfer-Encoding:quoted-printable\n\ngaga\n\n";
    char* enc_msg = NULL;
    char* dec_msg = NULL;

    PEP_STATUS status7 = MIME_encrypt_message(session, text4.c_str(), text4.length(), NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
//    PEP_STATUS status7 = MIME_encrypt_message(session, out_msg_plain, strlen(out_msg_plain), NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    TEST_ASSERT_MSG((status7 == PEP_STATUS_OK), "status7 == PEP_STATUS_OK");
    
    cout << enc_msg << endl;

    string text5 = enc_msg;
    
    PEP_decrypt_flags_t dec_flags;
    stringlist_t* keys_used;
    
    dec_flags = 0;
    char* modified_src = NULL;
    PEP_STATUS status8 = MIME_decrypt_message(session, text5.c_str(), text5.length(), &dec_msg, &keys_used, &rating, &dec_flags, &modified_src);
    TEST_ASSERT_MSG((status8 == PEP_STATUS_OK), "status8 == PEP_STATUS_OK");
    
    cout << dec_msg << endl;
    
    cout << "\nTesting encrypt_message() with enc_format = PEP_enc_none\n\n";

    message *msg7 = new_message(PEP_dir_outgoing);
    pEp_identity * me7 = new_identity("pep.test.alice@pep-project.org", NULL, PEP_OWN_USERID, "Alice Test");
    identity_list *to7 = new_identity_list(new_identity("pep.test.bob@pep-project.org", NULL, "42", "Bob Test"));
    msg7->from = me7;
    msg7->to = to7;
    msg7->shortmsg = strdup("My Subject");
    msg7->longmsg = strdup("This is some text.\n");

    message *enc7 = nullptr;
    PEP_STATUS status9 = encrypt_message(session, msg7, NULL, &enc7, PEP_enc_none, 0);
	std::cout << "encrypt_message returned " << std::dec << status9 << std::hex << " (0x" << status9 << ")" << std::dec << endl;
    TEST_ASSERT_MSG((status9 == PEP_UNENCRYPTED), "status9 == PEP_UNENCRYPTED");
    TEST_ASSERT_MSG((enc7 == nullptr), "enc7 == nullptr");
    TEST_ASSERT_MSG((msg7->shortmsg && msg7->longmsg), "msg7->shortmsg && msg7->longmsg");
    cout << msg7->shortmsg << "\n";
    cout << msg7->longmsg << "\n";
    TEST_ASSERT_MSG((strcmp(msg7->shortmsg, "My Subject") == 0), "strcmp(msg7->shortmsg, \"My Subject\") == 0");
    TEST_ASSERT_MSG((strcmp(msg7->longmsg, "This is some text.\n") == 0), "strcmp(msg7->longmsg, \"This is some text.\n\") == 0");
    
    cout << "\nfreeing messages…\n";
    free_message(msg7);
    free_message(msg6);
    free_message(msg5);
    free_message(msg4);
    free_message(msg3);
    free_message(msg2);
    free_message(enc_msg2);
    cout << "done.\n";

    free(enc_msg);
    free(dec_msg);    
}
