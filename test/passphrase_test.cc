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
#include "keymanagement.h"
#include "test_util.h"

using namespace std;

int main() {
    cout << "\n*** encrypt_for_identity_test ***\n\n";

    PEP_SESSION session;
    
    cout << "calling init()\n";
    PEP_STATUS status1 = init(&session);
    assert(status1 == PEP_STATUS_OK);
    assert(session);
    cout << "init() completed.\n";

    // Alice, my only friend, I love you --
    // not just that your name starts with an "A"
    const string alice_pub_key = slurp(
        "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    PEP_STATUS statuspub = import_key(
        session, 
        alice_pub_key.c_str(), 
        alice_pub_key.length(), 
        NULL);
    assert(statuspub == PEP_STATUS_OK);
    pEp_identity* alice = new_identity(
        "pep.test.alice@pep-project.org",
        "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
        PEP_OWN_USERID,
        "Alice Test");

    // Me, me, me
    const string pass_priv_key = slurp(
        "test_keys/priv/secret_key_with_passphrase.asc");
    PEP_STATUS statuspriv = import_key(
        session, 
        pass_priv_key.c_str(), 
        pass_priv_key.length(), 
        NULL);
    assert(statuspriv == PEP_STATUS_OK);
    pEp_identity* passphrase_id = new_identity(
        "passphrase@test.me", 
        "3DED854641A9694C5AC20E6555C174A6A00DB910",
        PEP_OWN_USERID, "passphrase");
    passphrase_id->me = true;
    PEP_STATUS mystatus = myself(session, passphrase_id);
    assert(mystatus == PEP_STATUS_OK);

    cout << "creating message…\n";
    identity_list* to_list = new_identity_list(alice); // to bob
    message* outgoing_message = new_message(PEP_dir_outgoing);
    assert(outgoing_message);
    outgoing_message->from = passphrase_id;
    outgoing_message->to = to_list;
    outgoing_message->shortmsg = strdup("shortmsg");
    outgoing_message->longmsg = strdup("longmsg");
    cout << "message created.\n";

    cout << "encrypting message as MIME multipart…\n";
    message* encrypted_msg = nullptr;
    cout << "calling encrypt_message()\n";
    PEP_STATUS status = encrypt_message(session, outgoing_message, NULL, &encrypted_msg, PEP_enc_PGP_MIME, 0);
    cout << "encrypt_message() returns " << std::hex << status << '.' << endl;
    assert(status == PEP_STATUS_OK);
    assert(encrypted_msg);
    cout << "message encrypted.\n";
    
    // TODO : check that indeed passphrase callback was called

    cout << "calling release()\n";
    release(session);
    return 0;
}
