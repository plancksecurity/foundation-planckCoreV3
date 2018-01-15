// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string.h>
#include "platform.h"
#include <iostream>
#include <fstream>
#include <assert.h>
#include "mime.h"
#include "message_api.h"

using namespace std;

void test_MIME_decrypt_message()
{
	static const std::string private_key =
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
        "\n"
        "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\n"
        "okyt7GheXlwKEtVQSAcH/NalK9Q+ckaQttA=\n"
        "=KACn\n"
        "-----END PGP PRIVATE KEY BLOCK-----\n"
        "\n";

    static const std::string mimetext =
        "To: denden@peptest.ch\r\n"
        "From: Lars Rohwedder <roker@pep-project.org>\r\n"
        "Subject: Test for ENGINE-322\r\n"
        "Message-ID: <4b2d328c-b284-e359-1c2c-fe136358b8a6@pep-project.org>\r\n"
        "Date: Thu, 28 Dec 2017 22:00:47 +0100\r\n"
        "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:52.0)\r\n"
        " Gecko/20100101 Thunderbird/52.5.0\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-Language: en-US\r\n"
        "Content-Transfer-Encoding: 8bit\r\n"
        "\r\n"
        "-----BEGIN PGP MESSAGE-----\r\n"
        "Charset: utf-8\r\n"
        "\r\n"
        "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\r\n"
        "=1lFj\r\n"
        "-----END PGP MESSAGE-----\r\n"
        "\r\n";

	PEP_SESSION session;
	PEP_STATUS status1 = init(&session);
	assert(status1 == PEP_STATUS_OK);
	assert(session);

	// import secret key
	identity_list* pk = NULL; 
	status1 = import_key( session, private_key.c_str(), private_key.size(), &pk );
	assert(status1 == PEP_STATUS_OK);
	std::cout << "Imported " << identity_list_length(pk) << " private key(s)." << endl;
	
	char* plaintext = nullptr;
	stringlist_t* keys_used = nullptr;
	PEP_rating rating;
	PEP_decrypt_flags_t dec_flags;
	
	PEP_STATUS status2 = MIME_decrypt_message(session, mimetext.c_str(), mimetext.length(),
		&plaintext, &keys_used, &rating, &dec_flags);
	
	std::cout << "MIME_decrypt_message returned " << std::dec << status2 << std::hex << " (0x" << status2 << ")" << std::dec << endl;
	
	assert(status2 == PEP_DECRYPTED);
	assert(plaintext);
	
	pEp_free(plaintext);
	
	identity_list* il = pk;
	while(il)
	{
		std::cout << "Delete test key \"" << il->ident->fpr << "\"" << endl;
		delete_keypair( session, il->ident->fpr );
		il = il->next;
	}
	free_identity_list(pk);
}


int main() {
    cout << "\n*** message_api_test ***\n\n";
    test_MIME_decrypt_message();

    PEP_SESSION session;
    
    cout << "calling init()\n";
    PEP_STATUS status1 = init(&session);
    assert(status1 == PEP_STATUS_OK);
    assert(session);
    cout << "init() completed.\n";

    // message_api test code

    cout << "creating message…\n";
    pEp_identity * me2 = new_identity("pep.test.alice@pep-project.org", NULL, PEP_OWN_USERID, "Alice Test");
    // pEp_identity * me2 = new_identity("test@nokey.plop", NULL, PEP_OWN_USERID, "Test no key");
    identity_list *to2 = new_identity_list(new_identity("pep.test.bob@pep-project.org", NULL, "42", "Bob Test"));
    // identity_list *to2 = new_identity_list(new_identity("still@nokey.blup", NULL, "42", "Still no key"));
    message *msg2 = new_message(PEP_dir_outgoing);
    assert(msg2);
    msg2->from = me2;
    msg2->to = to2;
    msg2->shortmsg = strdup("hello, world");
    msg2->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);
    cout << "message created.\n";

    char *text2 = nullptr;
    PEP_STATUS status2 = mime_encode_message(msg2, false, &text2);
    assert(status2 == PEP_STATUS_OK);
    assert(text2);

    cout << "decrypted:\n\n";
    cout << text2 << "\n";

    free(text2);

    cout << "encrypting message as MIME multipart…\n";
    message *enc_msg2 = nullptr;
    cout << "calling encrypt_message()\n";
    status2 = encrypt_message(session, msg2, NULL, &enc_msg2, PEP_enc_PGP_MIME, 0);
    cout << "encrypt_message() returns " << status2 << '.' << endl;
    assert(status2 == PEP_STATUS_OK);
    assert(enc_msg2);
    cout << "message encrypted.\n";
    
    status2 = mime_encode_message(enc_msg2, false, &text2);
    assert(status2 == PEP_STATUS_OK);
    assert(text2);

    cout << "encrypted:\n\n";
    cout << text2 << "\n";

    message *msg3 = nullptr;
    PEP_STATUS status3 = mime_decode_message(text2, strlen(text2), &msg3);
    assert(status3 == PEP_STATUS_OK);
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
    
    PEP_STATUS status4 = decrypt_message(session, enc_msg2, &msg4, &keylist4, &rating, &flags);
    assert(status4 == PEP_STATUS_OK);
    assert(msg4);
    assert(keylist4);
    assert(rating);
    PEP_comm_type ct = enc_msg2->from->comm_type;
    assert(ct == PEP_ct_pEp || ct == PEP_ct_pEp_unconfirmed || ct == PEP_ct_OpenPGP || ct == PEP_ct_OpenPGP_unconfirmed );

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
    assert(inFile3.is_open());

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
    assert(status5 == PEP_STATUS_OK);

    message *msg6 = nullptr;
    stringlist_t *keylist5 = nullptr;
    PEP_rating rating2;
    PEP_decrypt_flags_t flags2;
    PEP_STATUS status6 = decrypt_message(session, msg5, &msg6, &keylist5, &rating2, &flags2);
    assert(status6 == PEP_DECRYPT_NO_KEY);
    assert(msg6 == NULL);
    assert(keylist5 == NULL);
    assert(rating2 == PEP_rating_have_no_key);
    cout << "rating :" << rating2 << "\n";
    free_stringlist(keylist5);

    cout << "\nTesting MIME_encrypt_message / MIME_decrypt_message...\n\n";

    cout << "opening alice_bob_encrypt_test_plaintext_mime.eml for reading\n";
    ifstream inFile4 ("test_mails/alice_bob_encrypt_test_plaintext_mime.eml");
    assert(inFile4.is_open());
    
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
    assert(status7 == PEP_STATUS_OK);
    
    cout << enc_msg << endl;

    string text5 = enc_msg;
    
    PEP_decrypt_flags_t dec_flags;
    stringlist_t* keys_used;
    
    PEP_STATUS status8 = MIME_decrypt_message(session, text5.c_str(), text5.length(), &dec_msg, &keys_used, &rating, &dec_flags);
    assert(status8 == PEP_STATUS_OK);
    
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
    assert(status9 == PEP_UNENCRYPTED);
    assert(enc7 == nullptr);
    assert(msg7->shortmsg && msg7->longmsg);
    cout << msg7->shortmsg << "\n";
    cout << msg7->longmsg << "\n";
    assert(strcmp(msg7->shortmsg, "My Subject") == 0);
    assert(strcmp(msg7->longmsg, "This is some text.\n") == 0);
    
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
    cout << "calling release()\n";
    release(session);
    return 0;
}
