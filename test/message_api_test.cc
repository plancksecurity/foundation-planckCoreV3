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
	const std::string mimetext =
		"Return-Path: <roker@pep-project.org>\r\n"
		"X-Original-To: roker@pep-project.org\r\n"
		"Delivered-To: roker@pep-project.org\r\n"
		"Received: from localhost (localhost [127.0.0.1])\r\n"
		"	by dragon.pibit.ch (Postfix) with ESMTP id C4FF8171C055\r\n"
		"	for <roker@pep-project.org>; Tue, 26 Dec 2017 17:14:42 +0100 (CET)\r\n"
		"Received: from dragon.pibit.ch ([127.0.0.1])\r\n"
		"	by localhost (dragon.pibit.ch [127.0.0.1]) (amavisd-new, port 10024)\r\n"
		"	with ESMTP id GojZqayOfeAq for <roker@pep-project.org>;\r\n"
		"	Tue, 26 Dec 2017 17:14:39 +0100 (CET)\r\n"
		"To: Lars Rohwedder <roker@pep-project.org>\r\n"
		"From: Lars Rohwedder <roker@pep-project.org>\r\n"
		"Subject: Test mail PGP/INLINE\r\n"
		"Message-ID: <8fff4ca8-a8aa-f016-a7fd-39c98a9a4f43@pep-project.org>\r\n"
		"Date: Tue, 26 Dec 2017 17:14:38 +0100\r\n"
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
		"hQIMA+NkSS2yiGkeARAAgtW5xzq/ksfUIRxPZIDwGIANH0iLKhbnFbg/GssuyQOE\r\n"
		"+7rdevKX9UcxwBcRGJYs/aSMvY9zQE4tJy3ohf6+jnRzh3RH055A6+bsUWS/cex3\r\n"
		"fL7PtmQUT2PRXcXfrrk+oiCPXdJPVyRJXKGkKzwmpy7+U8mSSPoR3SIciFy/9CKs\r\n"
		"zhiTuQm8momz5gP/FpNyIU6E0xOdvyv9G90Y0qLzQyWFCY9fo3uRvKtvQmp2A0vj\r\n"
		"nI0rMBBnblLWLkLhTgEhsBSxi5/Emu2kzYXdhezb+IxuMrl7LhrZkFCSNnPWozJ7\r\n"
		"gyEcxK9tPOyK/SCYY+s9vg6D3F8mdJIT8Vi/87v1hQjvehc+xtiY/nNadaSDPWOh\r\n"
		"eWZ8FWVNRU3xowT5gyC75F8K+5IkhxsdmFGNznMzX9m+09fI515oVbDPe493JPNq\r\n"
		"TjKOVq406EFGIJ5+DGd1IDStUZuZBl4Z79bz9uF/vKCnvFzskTW69NypoDOe3+XL\r\n"
		"mP86vm3dUB3kWStHyWvH2RFbHnrbyHjZhQihsu8NdGBa3ZYatwlPhwVGaucSkrYM\r\n"
		"vSEgKyN+7XqQQIQSv6ncxzoNlZ7Cgoyh0BeaTIjDVH/0H6oUrljGO8UwcNhEOxGH\r\n"
		"WRBRI/emArMa8ro/tJ08jbFkRB1qiLSdfh0bufD0hWGGG16gXvvND4UgnVZ3VnzS\r\n"
		"6QGNwgYIqTQqXgsj/9PkKVaoZp3OyldpS/tq93Y4cES9DjSAcxN9MVgPIdvkGvaa\r\n"
		"MrKhpGu+prYEQJm1KfB4yTB+SuQOjngFiDXtsbN7jC7nCRpgQIjbCG3QKl8QUdrU\r\n"
		"Uy3OHuaGJUgKwy330Hi9cfCKD3lCBHr7XhSbZ/spuZudB5/bv6doQlrR9W2ccMAF\r\n"
		"RWsZAg7BXXzLvROgHCpcnNG/yHllQKpZ2REsUlbdNc2Sbw+tcjS1j18jGUwkSGhD\r\n"
		"j0hVQSYVJ1DN17QYPHV9w7WvHHw9QgDK0eDIkcykVAQqB25U+H61wg3HrQ73CFj2\r\n"
		"v0fyFYcSsCAj7LZnODLw6Mq+JzEIJUS1KPkJ4tiABXNCetwSUyJjaUlCfYHVE3Xi\r\n"
		"OjgNm1QLqjt2adK1Yi0gj7Go4CIFS4UE03WZfQkEh6y16ZSivAEQ9Wzy8E+Uy5VX\r\n"
		"diJQNPZ0VJozckp4wR+2Ao3yeBgQG9/zUbhihYBBGEPH6FmxscXcajssYrsbUh0D\r\n"
		"3IyncNEwrneiP430RhkkF9yQb+xwNxvYE0B+11PhuvtBBukDQjLSKN21mR8vBYBS\r\n"
		"kl1D/Z2Z388ObjPPXXGBpfWhhQyHKhPMJ0HMGUkCOf4IlmkH+vJt9a7Ex10URs1a\r\n"
		"KuFTB5EeNGsI6lQaze+mai7On1hI/wEC51ul5n46c75iuLRLzSTxJ/gjwg0gdHHZ\r\n"
		"5PLVTYfc58OXhiSDWhTvX+M+lWm49LQu+dCL3/pfLuR4D6Ytz/FDSFrSwNUQ7vOx\r\n"
		"3MBVK7dshY5IbTF3jbLr0fkdX6wmXapgjMF7KYS8FqxNUC/IEC1mCgSiHZDCA8TT\r\n"
		"WLXnnsGmB7eRAlYBpO2TAhhAhhg0aT+GhrvkZwROW4Keka+VGSt4R0+nKhrCuYkQ\r\n"
		"Vo5t3qUtVAo2ic/ktisa4rNPND0XQAcCi58=\r\n"
		"=vf0v\r\n"
		"-----END PGP MESSAGE-----\r\n"
		"\r\n";
	
	PEP_SESSION session;
	PEP_STATUS status1 = init(&session);
	assert(status1 == PEP_STATUS_OK);
	assert(session);

	char* plaintext = nullptr;
	stringlist_t* keys_used = nullptr;
	PEP_rating rating;
	PEP_decrypt_flags_t dec_flags;
	
	PEP_STATUS status2 = MIME_decrypt_message(session, mimetext.c_str(), mimetext.length(),
		&plaintext, &keys_used, &rating, &dec_flags);
	
	std::cout << "MIME_decrypt_message returned " << status2 << std::hex << " (0x" << status2 << ")" << endl;
	
	assert(status2 == PEP_STATUS_OK);
	assert(plaintext);
	
	pEp_free(plaintext);
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
    
    
    cout << "freeing messages…\n";
    free_message(msg4);
    free_message(msg3);
    free_message(msg2);
    free_message(enc_msg2);
    free_message(msg6);
    free_message(msg5);
    cout << "done.\n";

    free(enc_msg);
    free(dec_msg);
    cout << "calling release()\n";
    release(session);
    return 0;
}
