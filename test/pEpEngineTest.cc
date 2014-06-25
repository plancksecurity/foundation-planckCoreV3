#include <iostream>
#include <fstream>
#include <string>

#include <assert.h>
#include <string.h>

#include "../src/pEpEngine.h"
#include "../src/keymanagement.h"

#ifdef _WIN32
#define strdup _strdup
#endif

using namespace std;

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

	string cipher;

	cout << "opening msc.asc for reading\n";
	ifstream inFile ("msg.asc");
	assert(inFile.is_open());

	cout << "reading cipher text of msc.asc\n";
	while (!inFile.eof()) {
		static string line;
		getline(inFile, line);
		cipher += line + "\n";
	}
	inFile.close();

	cout << "\n" << cipher;

	char *buf_text;
	size_t buf_size;
	stringlist_t *keylist;

    cout << "calling decrypt_and_verify()\n";
    PEP_STATUS decrypt_result = decrypt_and_verify(session, cipher.c_str(), cipher.length(), &buf_text, &buf_size, &keylist);

    cout << "returning from decrypt_and_verify() with result == " << decrypt_result << "\n";
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

    string t1, t2, sig;

	cout << "\nopening t1.txt for reading\n";
	ifstream txtFile ("t1.txt");
	assert(txtFile.is_open());

	cout << "reading t1 from t1.txt\n";
	while (!txtFile.eof()) {
		static string line;
		getline(txtFile, line);
		t1 += line + "\r\n";
	}
	txtFile.close();
    assert(t1.size());
    t1.erase(t1.size()-2, 2);

	cout << "opening signature.asc for reading\n";
	ifstream sigFile ("signature.asc");
	assert(sigFile.is_open());

	cout << "reading sig from signature.asc\n";
	while (!sigFile.eof()) {
		static string line;
		getline(sigFile, line);
		sig += line + "\n";
	}
	sigFile.close();

    cout << "\ncalling verify_test()\n";
    PEP_STATUS verify_result = verify_text(session, t1.c_str(), t1.size(), sig.c_str(), sig.size(), &keylist);
    cout << "result = " << verify_result << "\n";
    assert(verify_result == PEP_VERIFIED || verify_result == PEP_VERIFIED_AND_TRUSTED);
    assert(keylist->value);
    cout << "signed with " << keylist->value << "\n";
    free_stringlist(keylist);

	cout << "\nopening t2.txt for reading\n";
	ifstream txt2File ("t2.txt");
	assert(txt2File.is_open());

	cout << "reading t2 from t2.txt\n";
	while (!txt2File.eof()) {
		static string line;
		getline(txt2File, line);
		t2 += line + "\r\n";
	}
	txt2File.close();
    assert(t2.size());
    t1.erase(t2.size()-2, 2);

    cout << "\ncalling verify_test()\n";
    verify_result = verify_text(session, t2.c_str(), t2.size(), sig.c_str(), sig.size(), &keylist);
    cout << "result = " << verify_result << "\n";
    assert(verify_result == PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH);
    free_stringlist(keylist);

    keylist = new_stringlist("FA7261F7");

    cout << "\ncalling encrypt_and_sign()\n";
    PEP_STATUS encrypt_result = encrypt_and_sign(session, keylist, plain.c_str(), plain.length(), &buf_text, &buf_size);
    
    cout << "returning from encrypt_and_sign() with result == " << encrypt_result << "\n";
    assert(encrypt_result == PEP_STATUS_OK);
    free_stringlist(keylist);

    buf_text[buf_size] = 0;
    string cipher2(buf_text);
    cout << "\n" << cipher2;
    pEp_free(buf_text);

	cout << "\nfinding English safeword for 2342...\n";
	char * word;
	size_t wsize;
	safeword(session, 2342, "en", &word, &wsize);
	assert(word);
	cout << "the safeword for 2342 is " << word << "\n";
    pEp_free(word);

    string fingerprint = "4942 2235 FC99 585B 891C  6653 0C7B 109B FA72 61F7";
    char * words;

    cout << "\nfinding German safewords for " << fingerprint << "...\n";
    safewords(session, fingerprint.c_str(), "de", &words, &wsize, 5);
    assert(words);
    cout << words << "\n";
    pEp_free(words);

	pEp_identity *identity;

    identity = new_identity(
            strdup("leon.schumacher@digitalekho.com"),
            strdup("8BD08954C74D830EEFFB5DEB2682A17F7C87F73D"),
            strdup("23"),
            strdup("Leon Schumacher")
        );
	identity->comm_type = PEP_ct_pEp;

	cout << "\nsetting identity...\n";
	PEP_STATUS pep_set_result = set_identity(session, identity);
	assert(pep_set_result == PEP_STATUS_OK);
    free_identity(identity);
	get_identity(session, "leon.schumacher@digitalekho.com", &identity);
	assert(identity);
	cout << "set: " << identity->address << ", " << identity->fpr << ", " << identity->user_id << ", " << identity->username << "\n";
    free_identity(identity);

    stringlist_t *addresses = new_stringlist("leon.schumacher@digitalekho.com");
    PEP_comm_type comm_type;
    cout << "\nretrieving communication type for leon.schumacher@digitalekho.com\n";
    PEP_STATUS oct_result = outgoing_comm_type(session, addresses, &comm_type);
    cout << "communication type is " << comm_type << "\n";
    free_stringlist(addresses);
    assert(oct_result == PEP_STATUS_OK && comm_type == PEP_ct_pEp);

    stringlist_t *addresses2 = new_stringlist("leon.schumacher@digitalekho.com");
    stringlist_add(addresses2, "this.email@is.invalid");
    cout << "\nretrieving communication type for an unknown address\n";
    oct_result = outgoing_comm_type(session, addresses2, &comm_type);
    cout << "communication type is " << comm_type << "\n";
    cout << "status is " << oct_result << "\n";
    free_stringlist(addresses2);
    assert(oct_result == PEP_STATUS_OK && comm_type == PEP_ct_no_encryption);

    cout << "\ngenerating key for testuser\n";
    identity = new_identity(
            strdup("testuser@pibit.ch"),
            NULL,
            strdup("423"),
            strdup("Alfred E. Neuman")
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

    cout << "finding key for outlooktest@dingens.org\n";
    PEP_STATUS find_keys_status = find_keys(session, "outlooktest@dingens.org", &keylist);
    assert(find_keys_status == PEP_STATUS_OK);
    assert(keylist);
    cout << "found: " << keylist->value << "\n";
    assert(keylist->next == NULL);
    free_stringlist(keylist);

    cout << "searching for vb@ulm.ccc.de on keyserver\n";
    PEP_STATUS recv_key_status = recv_key(session, "vb@ulm.ccc.de");
    assert(recv_key_status == PEP_STATUS_OK);

    cout << "sending vb@ulm.ccc.de to keyserver\n";
    PEP_STATUS send_key_status = send_key(session, "vb@ulm.ccc.de");
    assert(recv_key_status == PEP_STATUS_OK);

	cout << "\ncalling release()\n";
	release(session);
	return 0;
}
