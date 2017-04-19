// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <iostream>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <assert.h>
#include <string.h>

#include "../src/pEpEngine.h"
#include "../src/keymanagement.h"


using namespace std;

typedef std::string Buffer;

// no C++11, yet? So do our own implementation:
namespace{
    std::string to_string(unsigned long u)
    {
        char buf[32];
        snprintf(buf,31, "%lu", u);
        return buf;
    }
    
    std::string status(PEP_STATUS status)
    {
        char buf[32] = {0};
        if(status==0)
        {
            return "PEP_STATUS_OK";
        }else{
            if(status>0)
            {
                snprintf(buf,31, "%u (0x%x)", status, status);
            }else{
                snprintf(buf,31, "%d", status);
            }
        }
        return buf;
    }

} // end of anonymous namespace


Buffer ReadFileIntoMem(const char *fname){
    cout << "opening " << fname << " for reading\n";
    ifstream txtFile (fname, ifstream::binary);
    assert(txtFile.is_open());
    if (!txtFile)
    {
        throw std::runtime_error( "error: cannot open file \"" + std::string(fname) + "\"" );
    }

    Buffer buffer;

    // get length of file:
    txtFile.seekg (0, txtFile.end);
    const size_t length = txtFile.tellg();
    txtFile.seekg (0, txtFile.beg);
    buffer.resize(length);

    cout << "Reading " << length << " characters... ";
    txtFile.read (&buffer[0], length);

    if (!txtFile)
    {
        throw std::runtime_error( "error: only " + to_string(txtFile.gcount()) + " could be read from file" + fname );
    }

    cout << "all characters read successfully." << std::endl;
    return buffer;
}


int main(int argc, char* argv[])
{
    PEP_SESSION session;

    cout << "calling init()\n";
    PEP_STATUS init_result = init(&session);
    
    cout << "returning from init() with result == " << status(init_result) << endl;
    assert(init_result == PEP_STATUS_OK);

    PEP_SESSION second_session;
    cout << "second session test\n";
    PEP_STATUS second_init_result = init(&second_session);
    cout << "returning from second init() with result == " << status(second_init_result) << endl;
    assert(second_init_result == PEP_STATUS_OK);
    assert(second_session);
    cout << "dropping second session\n";
    release(second_session);

    cout << "logging test\n";
    log_event(session, "log test", "pEp Engine Test", "This is a logging test sample.", "please ignore this line");

    // Our test user :
    // pEp Test Alice (test key don't use) <pep.test.alice@pep-project.org>
    //                                 6FF00E97 -- won't work as search term with NetPGP
    //                         A9411D176FF00E97 -- won't work as search term with NetPGP
    // 4ABE3AAF59AC32CFE4F86500A9411D176FF00E97 -- full key fingerprint
    // 
    // Other peers :
    // pEp Test Bob (test key, don't use) <pep.test.bob@pep-project.org> 
    //                                 C9C2EE39 -- won't work as search term with NetPGP
    //                         59BFF488C9C2EE39 -- won't work as search term with NetPGP
    // BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39 -- full key fingerprint
    // 
    // pEp Test John (test key, don't use) <pep.test.john@pep-project.org>
    //                                 70DCF575 -- won't work as search term with NetPGP
    //                         135CD6D170DCF575 -- won't work as search term with NetPGP
    // AA2E4BEB93E5FE33DEFD8BE1135CD6D170DCF575 -- full key fingerprint

    const char *kflist[] = {
        "0x6FF00E97.asc",
        "0xC9C2EE39.asc",
        "0x70DCF575.asc",
        NULL
    };

    const char** kf = kflist;
    while(*kf){
        const Buffer k_user_buffer =  ReadFileIntoMem(*kf);
        cout << "import_key(" << *kf << ")\n";
        PEP_STATUS import_status = import_key(session, k_user_buffer.data(), k_user_buffer.size(), NULL);
        assert(import_status == PEP_STATUS_OK);
        cout << "successfully imported key\n";
        kf++;
    }

    const Buffer cipher_buffer = ReadFileIntoMem("msg.asc");
    cout << "\n" << cipher_buffer.data();

    char *buf_text = NULL;
    size_t buf_size = 0;
    stringlist_t *keylist;

    cout << "calling decrypt_and_verify()\n";
    PEP_STATUS decrypt_result = decrypt_and_verify(session, cipher_buffer.data(), cipher_buffer.size(), NULL, 0, &buf_text, &buf_size, &keylist);

    cout << "returning from decrypt_and_verify() with result == " << status(decrypt_result) << endl;
    assert(decrypt_result == PEP_DECRYPTED_AND_VERIFIED);
    assert(buf_text);
    assert(keylist);

    for (stringlist_t *_keylist=keylist; _keylist!=NULL; _keylist=_keylist->next) {
        assert(_keylist->value);
        cout << "signed with " << _keylist->value << endl;
    }

    free_stringlist(keylist);
    buf_text[buf_size] = 0;
    const string plain(buf_text);
    pEp_free(buf_text);
    cout << "\n" << plain;

    const Buffer t1_buffer = ReadFileIntoMem("t1.txt");
    const Buffer sig_buffer = ReadFileIntoMem("signature.asc");

    cout << "\ncalling verify_text()\n";
    PEP_STATUS verify_result = verify_text(session, t1_buffer.data(), t1_buffer.size(), sig_buffer.data(), sig_buffer.size(), &keylist);
    cout << "returning from verify_text() with result == " << status(verify_result) << endl;
    assert(verify_result == PEP_VERIFIED || verify_result == PEP_VERIFIED_AND_TRUSTED);
    assert(keylist->value);
    cout << "signed with " << keylist->value << endl;
    free_stringlist(keylist);

    const Buffer t2_buffer = ReadFileIntoMem("t2.txt");

    cout << "\ncalling verify_text()\n";
    verify_result = verify_text(session, t2_buffer.data(), t2_buffer.size(), sig_buffer.data(), sig_buffer.size(), &keylist);
    assert(verify_result == PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH);
    free_stringlist(keylist);

    keylist = new_stringlist("4ABE3AAF59AC32CFE4F86500A9411D176FF00E97");
    stringlist_add(keylist, "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39");
    stringlist_add(keylist, "AA2E4BEB93E5FE33DEFD8BE1135CD6D170DCF575");

    buf_text = NULL;
    buf_size = 0;

    cout << "\ncalling encrypt_and_sign()\n";
    PEP_STATUS encrypt_result = encrypt_and_sign(session, keylist, plain.c_str(), plain.length(), &buf_text, &buf_size);
    cout << "returning from encrypt_and_sign() with result == " << status(encrypt_result) << endl;
    assert(encrypt_result == PEP_STATUS_OK);
    free_stringlist(keylist);

    buf_text[buf_size] = '\0';
    const string cipher2(buf_text);
    cout << "\n" << cipher2;
    pEp_free(buf_text);

    cout << "\nfinding English trustword for 2342...\n";
    char * word = NULL;
    size_t wsize;
    trustword(session, 2342, "en", &word, &wsize);
    assert(word);
    cout << "the English trustword for 2342 is " << word << endl;
    pEp_free(word);
    cout << "\nfinding French trustword for 2342...\n";
    trustword(session, 2342, "fr", &word, &wsize);
    assert(word);
    cout << "the French trustword for 2342 is " << word << endl;
    pEp_free(word);

    const string fingerprint = "4942 2235 FC99 585B 891C  6653 0C7B 109B FA72 61F7";
    char * words = NULL;

    cout << "\nfinding German trustwords for " << fingerprint << "...\n";
    trustwords(session, fingerprint.c_str(), "de", &words, &wsize, 5);
    assert(words);
    cout << words << endl;
    pEp_free(words);

    pEp_identity* identity  = new_identity(
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
    cout << "set: " << identity->address << ", " << identity->fpr << ", " << identity->user_id << ", " << identity->username << endl;

    PEP_STATUS get_trust_result = get_trust(session, identity);
    assert(get_trust_result == PEP_STATUS_OK);
    cout << "trust of " << identity->user_id << " is " << identity->comm_type << endl;

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
    cout << "generate_keypair() exits with " << status(generate_status) << endl;
    assert(generate_status == PEP_STATUS_OK);
    cout << "generated key is " << identity->fpr << endl;

    const string key(identity->fpr);
    free_identity(identity);

    char *key_data = NULL;
    size_t size = 0;

    cout << "export_key()\n\n";
    PEP_STATUS export_status = export_key(session, key.c_str(), &key_data, &size);
    cout << "export_key() exits with " << status(export_status) << endl;
    assert(export_status == PEP_STATUS_OK);
    cout << key_data << "\n\n";

    cout << "deleting key pair " << key.c_str() << endl;
    PEP_STATUS delete_status = delete_keypair(session, key.c_str());
    cout << "delete_keypair() exits with " << status(delete_status) << endl;
    assert(delete_status == PEP_STATUS_OK);
    
    cout << "import_key()\n";
    PEP_STATUS import_status = import_key(session, key_data, size, NULL);
    assert(import_status == PEP_STATUS_OK);
    cout << "successfully imported key\n";

    pEp_free(key_data);
    key_data=NULL;

    cout << "deleting key " << key.c_str() << " again\n";
    delete_status = delete_keypair(session, key.c_str());
    cout << "delete_keypair() exits with " << status(delete_status) << endl;
    assert(delete_status == PEP_STATUS_OK);

    cout << "finding key for pep.test.john@pep-project.org\n";
    PEP_STATUS find_keys_status = find_keys(session, "pep.test.john@pep-project.org", &keylist);
    cout << "find_keys() exits with " << status(find_keys_status) << endl;
    assert(find_keys_status == PEP_STATUS_OK);
    assert(keylist);
    cout << "found: " << keylist->value << endl;
    assert(keylist->next == NULL);
    free_stringlist(keylist);

    cout << "searching for vb@ulm.ccc.de on keyserver\n";
    PEP_STATUS recv_key_status = recv_key(session, "vb@ulm.ccc.de");
    cout << "recv_key() exits with " << status(recv_key_status) << endl;
    assert(recv_key_status == PEP_STATUS_OK);

    cout << "sending vb@ulm.ccc.de to keyserver\n";
    PEP_STATUS send_key_status = send_key(session, "vb@ulm.ccc.de");
    cout << "send_key() exits with " << status(send_key_status) << endl;
    assert(send_key_status == PEP_STATUS_OK);

    PEP_comm_type tcomm_type;
    PEP_STATUS tstatus = get_key_rating(session, "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39", &tcomm_type);
    cout << "get_key_rating() exits with " << tstatus << endl;
    assert(tstatus == PEP_STATUS_OK);
    assert(tcomm_type == PEP_ct_OpenPGP_unconfirmed);
    
    cout << "\ncalling release()\n";
    cout << endl << "End of pEpEngineTest for engine version " << get_engine_version() << endl;

    release(session);
    return 0;
}
