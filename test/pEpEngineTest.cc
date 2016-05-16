#include <iostream>
#include <fstream>
#include <string>

#include <assert.h>
#include <string.h>

#include "../src/pEpEngine.h"
#include "../src/keymanagement.h"

using namespace std;

void ReadFileIntoMem(const char *fname, char* &buffer, size_t &length){
    buffer = NULL;
    length = 0;
	cout << "opening " << fname << " for reading\n";
	ifstream txtFile (fname, ifstream::binary);
	assert(txtFile.is_open());
    if (txtFile) {
        // get length of file:
        txtFile.seekg (0, txtFile.end);
        length = txtFile.tellg();
        txtFile.seekg (0, txtFile.beg);

        buffer = new char [length+1];

        cout << "Reading " << length << " characters... ";
        txtFile.read (buffer,length);
        buffer[length]='\0';

        if (txtFile)
          cout << "all characters read successfully.\n";
        else
          cout << "error: only " << txtFile.gcount() << " could be read\n";
        txtFile.close();
    }

	txtFile.close();
    assert(buffer);
    assert(length);
}

int main(int argc, char* argv[])
{
	PEP_SESSION session;

	cout << "calling init()\n";
	PEP_STATUS init_result = init(&session);
	
    cout << "returning from init() with result == " << init_result << "\n";
	assert(init_result == PEP_STATUS_OK);

    PEP_SESSION second_session;
    cout << "second session test\n";
    PEP_STATUS second_init_result = init(&second_session);
	cout << "returning from second init() with result == " << second_init_result << "\n";
    assert(second_init_result == PEP_STATUS_OK);
    assert(second_session);
    cout << "dropping second session\n";
	release(second_session);

	cout << "logging test\n";
	log_event(session, "log test", "pEp Enginge Test", "This is a logging test sample.", "please ignore this line");

    // Our test user :
    // pEp Test Alice (test key don't use) <pep.test.alice@pep-project.org>
    //         6FF00E97
    // A9411D176FF00E97
    // 
    // Other peers :
    // pEp Test Bob (test key, don't use) <pep.test.bob@pep-project.org> 
    //         C9C2EE39
    // 59BFF488C9C2EE39
    // 
    // pEp Test John (test key, don't use) <pep.test.john@pep-project.org>
    //         70DCF575
    // 135CD6D170DCF575

    const char *kflist[] = {
        "0x6FF00E97.asc",
        "0xC9C2EE39.asc",
        "0x70DCF575.asc",
        NULL
    };
    const char** kf = kflist;
    while(*kf){
        char * k_user_buffer = NULL;
        size_t k_user_length = 0;
        ReadFileIntoMem(*kf, k_user_buffer, k_user_length);
        cout << "import_key(" << *kf << ")\n";
        PEP_STATUS import_status = import_key(session, k_user_buffer, k_user_length);
        assert(import_status == PEP_STATUS_OK);
        cout << "successfully imported key\n";
        delete[] k_user_buffer;
        kf++;
    }

    char * cipher_buffer = NULL;
    size_t cipher_length = 0;
    ReadFileIntoMem("msg.asc", cipher_buffer, cipher_length);

	cout << "\n" << cipher_buffer;

	char *buf_text = NULL;
	size_t buf_size = 0;
	stringlist_t *keylist;

    cout << "calling decrypt_and_verify()\n";
    PEP_STATUS decrypt_result = decrypt_and_verify(session, cipher_buffer, cipher_length, &buf_text, &buf_size, &keylist);

    cout << "returning from decrypt_and_verify() with result == 0x" << std::hex << decrypt_result << "\n";
    assert(decrypt_result == PEP_DECRYPTED_AND_VERIFIED);
    assert(buf_text);
    assert(keylist);

    for (stringlist_t *_keylist=keylist; _keylist!=NULL; _keylist=_keylist->next) {
        assert(_keylist->value);
        cout << "signed with " << _keylist->value << "\n";
    }

    free_stringlist(keylist);
    buf_text[buf_size] = 0;
    string plain(buf_text);
    pEp_free(buf_text);
    cout << "\n" << plain;

    char * t1_buffer = NULL;
    size_t t1_length = 0;
    ReadFileIntoMem("t1.txt", t1_buffer, t1_length);

    char * sig_buffer = NULL;
    size_t sig_length = 0;
    ReadFileIntoMem("signature.asc", sig_buffer, sig_length);

    cout << "\ncalling verify_text()\n";
    PEP_STATUS verify_result = verify_text(session, t1_buffer, t1_length, sig_buffer, sig_length, &keylist);
    cout << "returning from verify_text() with result == " << verify_result << "\n";
    assert(verify_result == PEP_VERIFIED || verify_result == PEP_VERIFIED_AND_TRUSTED);
    assert(keylist->value);
    cout << "signed with " << keylist->value << "\n";
    free_stringlist(keylist);

    char * t2_buffer = NULL;
    size_t t2_length = 0;
    ReadFileIntoMem("t2.txt", t2_buffer, t2_length);

    cout << "\ncalling verify_text()\n";
    verify_result = verify_text(session, t2_buffer, t2_length, sig_buffer, sig_length, &keylist);
    assert(verify_result == PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH);
    free_stringlist(keylist);

    keylist = new_stringlist("A9411D176FF00E97");
    stringlist_add(keylist, "59BFF488C9C2EE39");
    stringlist_add(keylist, "135CD6D170DCF575");

	buf_text = NULL;
	buf_size = 0;

    cout << "\ncalling encrypt_and_sign()\n";
    PEP_STATUS encrypt_result = encrypt_and_sign(session, keylist, plain.c_str(), plain.length(), &buf_text, &buf_size);
    cout << "returning from encrypt_and_sign() with result == " << encrypt_result << "\n";
    assert(encrypt_result == PEP_STATUS_OK);
    free_stringlist(keylist);

    buf_text[buf_size] = 0;
    string cipher2(buf_text);
    cout << "\n" << cipher2;
    pEp_free(buf_text);

    delete[] cipher_buffer;
    delete[] t1_buffer;
    delete[] sig_buffer;
    delete[] t2_buffer;

	cout << "\nfinding English trustword for 2342...\n";
	char * word;
	size_t wsize;
	trustword(session, 2342, "en", &word, &wsize);
	assert(word);
	cout << "the trustword for 2342 is " << word << "\n";
    pEp_free(word);

    string fingerprint = "4942 2235 FC99 585B 891C  6653 0C7B 109B FA72 61F7";
    char * words;

    cout << "\nfinding German trustwords for " << fingerprint << "...\n";
    trustwords(session, fingerprint.c_str(), "de", &words, &wsize, 5);
    assert(words);
    cout << words << "\n";
    pEp_free(words);

	pEp_identity *identity;

    identity = new_identity(
            "leon.schumacher@digitalekho.com",
            "8BD08954C74D830EEFFB5DEB2682A17F7C87F73D",
            "23",
            "Leon Schumacher"
        );
	identity->comm_type = PEP_ct_pEp;

	cout << "\nsetting identity...\n";
	PEP_STATUS pep_set_result = set_identity(session, identity);
	assert(pep_set_result == PEP_STATUS_OK);
    free_identity(identity);
	get_identity(session, "leon.schumacher@digitalekho.com", "23", &identity);
	assert(identity);
	cout << "set: " << identity->address << ", " << identity->fpr << ", " << identity->user_id << ", " << identity->username << "\n";

    PEP_STATUS get_trust_result = get_trust(session, identity);
    assert(get_trust_result == PEP_STATUS_OK);
    cout << "trust of " << identity->user_id << " is " << identity->comm_type << "\n";

    free_identity(identity);

    cout << "\ngenerating key for testuser\n";
    identity = new_identity(
            "testuser@pibit.ch",
            NULL,
            "423",
            "Alfred E. Neuman"
        );
    assert(identity);
    PEP_STATUS generate_status = generate_keypair(session, identity);
    cout << "generate_keypair() exits with " << generate_status << "\n";
    assert(generate_status == PEP_STATUS_OK);
    cout << "generated key is " << identity->fpr << "\n";

    string key(identity->fpr);
    free_identity(identity);

    char *key_data;
    size_t size;

    cout << "export_key()\n\n";
    PEP_STATUS export_status = export_key(session, key.c_str(), &key_data, &size);
    cout << "export_key() exits with " << export_status << "\n";
    assert(export_status == PEP_STATUS_OK);
    cout << key_data << "\n\n";

    cout << "deleting key pair " << key.c_str() << "\n";
    PEP_STATUS delete_status = delete_keypair(session, key.c_str());
    cout << "delete_keypair() exits with " << delete_status << "\n";
    assert(delete_status == PEP_STATUS_OK);
    
    cout << "import_key()\n";
    PEP_STATUS import_status = import_key(session, key_data, size);
    assert(import_status == PEP_STATUS_OK);
    cout << "successfully imported key\n";

    pEp_free(key_data);

    cout << "deleting key " << key.c_str() << " again\n";
    delete_status = delete_keypair(session, key.c_str());
    cout << "delete_keypair() exits with " << delete_status << "\n";
    assert(delete_status == PEP_STATUS_OK);

    cout << "finding key for pep.test.john@pep-project.org\n";
    PEP_STATUS find_keys_status = find_keys(session, "pep.test.john@pep-project.org", &keylist);
    cout << "find_keys() exits with " << find_keys_status << "\n";
    assert(find_keys_status == PEP_STATUS_OK);
    assert(keylist);
    cout << "found: " << keylist->value << "\n";
    assert(keylist->next == NULL);
    free_stringlist(keylist);

    cout << "searching for vb@ulm.ccc.de on keyserver\n";
    PEP_STATUS recv_key_status = recv_key(session, "vb@ulm.ccc.de");
    cout << "recv_key() exits with " << recv_key_status << "\n";
    assert(recv_key_status == PEP_STATUS_OK);

    cout << "sending vb@ulm.ccc.de to keyserver\n";
    PEP_STATUS send_key_status = send_key(session, "vb@ulm.ccc.de");
    cout << "send_key() exits with " << send_key_status << "\n";
    assert(send_key_status == PEP_STATUS_OK);

    PEP_comm_type tcomm_type;
    PEP_STATUS tstatus = get_key_rating(session, "59BFF488C9C2EE39", &tcomm_type);
    cout << "get_key_rating() exits with " << tstatus << "\n";
    assert(tstatus == PEP_STATUS_OK);
    assert(tcomm_type == PEP_ct_OpenPGP_unconfirmed);
    
	cout << "\ncalling release()\n";
	release(session);
	return 0;
}
