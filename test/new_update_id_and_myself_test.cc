// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <iostream>
#include <iostream>
#include <fstream>
#include <string>
#include <cstring> // for strcmp()
#include <assert.h>
#include "pEpEngine.h"
#include "message_api.h"
#include "keymanagement.h"
#include "test_util.h"

using namespace std;

int main() {
    cout << "\n*** test update_identity and myself ***\n\n";
    
    test_init();
    
    PEP_SESSION session;
    
    cout << "calling init()\n";
    PEP_STATUS status = init(&session);
    assert(status == PEP_STATUS_OK);
    assert(session);
    cout << "init() completed.\n";
    cout << endl;
    cout << "***********************************************************************" << endl;
    cout << "* Section I. myself()" << endl;
    cout << "***********************************************************************" << endl << endl;

    // Create id with no key
    cout << "Creating new own id with no key for : ";
    char *uniqname = strdup("AAAAtestuser@testdomain.org");
    srandom(time(NULL));
    for(int i=0; i < 4;i++)
        uniqname[i] += random() & 0xf;
    
    cout << uniqname << "\n";
    
    const char* own_user_id = get_new_uuid();
    const char* start_username = "Unser Testkandidat";

    pEp_identity * new_me = new_identity(uniqname, NULL, own_user_id, start_username);
    
    cout << "***********************************************************************" << endl;
    cout << "* I: 1. myself() on id with no record in the DB and no input fpr" << endl;
    cout << "***********************************************************************" << endl << endl;
    status = myself(session, new_me);
    assert(status == PEP_STATUS_OK);
    assert(new_me->fpr);
    
    cout << "PASS: myself() generated fingerprint ";
    cout << new_me->fpr << endl << endl;

    char* generated_fpr = strdup(new_me->fpr);
    
    assert(new_me->comm_type == PEP_ct_pEp);
    
    free_identity(new_me);

    cout << "***********************************************************************" << endl;
    cout << "* I: 2. myself() on id with no input fpr and a record in the DB" << endl;
    cout << "***********************************************************************" << endl << endl;

    new_me = new_identity(uniqname, NULL, own_user_id, NULL);
    status = myself(session, new_me);
    assert(status == PEP_STATUS_OK);
    
    assert(new_me->fpr);
    assert(strcmp(new_me->fpr, generated_fpr) == 0);
    assert(new_me->username);
    assert(strcmp(new_me->username, start_username) == 0);
    assert(new_me->user_id);
    assert(new_me->comm_type == PEP_ct_pEp);
    
    char* default_own_id = NULL;
    status = get_userid_alias_default(session, own_user_id, &default_own_id);
    if (status == PEP_CANNOT_FIND_ALIAS) {
        // Ok, we presume our own id above is the default (should be true if there was no existing DB as in test env)
        default_own_id = strdup(own_user_id);
    }

    assert(strcmp(new_me->user_id, default_own_id) == 0);
    
    cout << "PASS: myself() retrieved the correct fpr, username and default user id" << endl << endl;

    free_identity(new_me);
     
    cout << "****************************************************************************************" << endl;
    cout << "* I: 3. myself() on id with no input fpr, a different user_id, and a record in the DB" << endl;
    cout << "****************************************************************************************" << endl << endl;

    const char* alias_id = "Huss Es El Mejor Presidente Del Mundo!";

    new_me = new_identity(uniqname, NULL, alias_id, NULL);
    status = myself(session, new_me);
    assert(status == PEP_STATUS_OK);
    
    assert(new_me->fpr);
    assert(strcmp(new_me->fpr, generated_fpr) == 0);
    assert(new_me->username);
    assert(strcmp(new_me->username, start_username) == 0);
    assert(new_me->user_id);
    assert(strcmp(new_me->user_id, default_own_id) == 0);
    assert(new_me->comm_type == PEP_ct_pEp);
    
    char* tmp_def = NULL;
    
    status = get_userid_alias_default(session, alias_id, &tmp_def);
    assert(status == PEP_STATUS_OK);
    assert(strcmp(tmp_def, default_own_id) == 0);

    cout << "PASS: myself() retrieved the correct fpr, username and default user id, and put the right alias in for the default";
    cout << endl << endl;
    
    free(tmp_def);
    free_identity(new_me);

    cout << "****************************************************************************************" << endl;
    cout << "* I: 4. myself(), replace fpr" << endl;
    cout << "****************************************************************************************" << endl << endl;

    new_me = new_identity(uniqname, NULL, alias_id, start_username);
    status = generate_keypair(session, new_me);
    assert(new_me->fpr);
    
    cout << "Generated fingerprint ";
    cout << new_me->fpr << "\n";

    char* new_fpr = strdup(new_me->fpr);

    status = set_own_key(session, new_me, new_fpr);
    assert(status == PEP_STATUS_OK);
    assert(new_me->fpr);
    assert(strcmp(new_me->fpr, generated_fpr) != 0);
    assert(strcmp(new_me->fpr, new_fpr) == 0);
    assert(new_me->username);
    assert(strcmp(new_me->username, start_username) == 0);
    assert(new_me->user_id);
    assert(strcmp(new_me->user_id, default_own_id) == 0);
    assert(new_me->me);
    assert(new_me->comm_type == PEP_ct_pEp);

    cout << "PASS: myself() set and retrieved the new fpr, username and default user id, and put the right alias in for the default";
    cout << endl << endl;

    // since that worked, we'll set it back as the default
    free(new_me->fpr);
    new_me->fpr = strdup(generated_fpr);
    new_me->comm_type = PEP_ct_unknown;
    status = set_own_key(session, new_me, generated_fpr);
    assert(status == PEP_STATUS_OK);
    assert(strcmp(new_me->fpr, generated_fpr) == 0);
    assert(new_me->comm_type == PEP_ct_pEp);
    
    cout << "****************************************************************************************" << endl;
    cout << "* I: 5. myself(), replace fpr, revoke key" << endl;
    cout << "****************************************************************************************" << endl << endl;

    status = revoke_key(session, generated_fpr, "Because it's fun");
    assert (status == PEP_STATUS_OK);
    
    new_me = new_identity(uniqname, NULL, alias_id, start_username);
    
    status = set_own_key(session, new_me, new_fpr);
    assert(status == PEP_STATUS_OK);
    assert(new_me->fpr);
    assert(strcmp(new_me->fpr, generated_fpr) != 0);
    assert(new_me->username);
    assert(strcmp(new_me->username, start_username) == 0);
    assert(new_me->user_id);
    assert(strcmp(new_me->user_id, default_own_id) == 0);
    assert(new_me->me);
    assert(new_me->comm_type == PEP_ct_pEp);
    
    cout << "PASS: myself() retrieved the new fpr, username and default user id, and put the right alias in for the default";
    cout << endl << endl;
        
    cout << "***********************************************************************" << endl;
    cout << "* Section II. update_identity()" << endl;
    cout << "***********************************************************************" << endl << endl;

    cout << "****************************************************************************************" << endl;
    cout << "* II: 1. update_identity() - get identity with matching address and user_id and username" << endl;
    cout << "****************************************************************************************" << endl << endl;    
    // 1. create original identity
    const char* alex_address = "pep.test.alexander@peptest.ch";
    const char* alex_fpr = "3AD9F60FAEB22675DB873A1362D6981326B54E4E";
    const char* alex_userid = "Alex";
    const char* alex_username = "SuperDuperAlex";
    const string alex_pub_key = slurp("test_keys/pub/pep.test.alexander-0x26B54E4E_pub.asc");
    
    PEP_STATUS statuspub = import_key(session, alex_pub_key.c_str(), alex_pub_key.length(), NULL);
    assert(statuspub == PEP_STATUS_OK);

    pEp_identity* alex = new_identity(alex_address, alex_fpr, alex_userid, alex_username);

    // 2. set identity
    status = set_identity(session, alex);
    assert(status == PEP_STATUS_OK);
    free_identity(alex);
            
    alex = new_identity(alex_address, NULL, alex_userid, alex_username); 
    status = update_identity(session, alex);
    assert(status == PEP_STATUS_OK);
    assert(alex->fpr);
    assert(strcmp(alex->fpr, alex_fpr) == 0);
    assert(alex->username);
    assert(strcmp(alex->username, alex_username) == 0);
    assert(alex->user_id);
    assert(strcmp(alex->user_id, alex_userid) == 0);
    assert(!alex->me); 
    assert(alex->comm_type == PEP_ct_OpenPGP_unconfirmed);
    assert(strcmp(alex->address, alex_address) == 0);

    cout << "PASS: update_identity() correctly retrieved extant record with matching address, id, and username" << endl << endl;
    free_identity(alex);

    cout << "****************************************************************************************" << endl;
    cout << "* II: 2. update_identity() - get identity with matching address and user_id and new username" << endl;
    cout << "****************************************************************************************" << endl << endl;    

    const char* new_username = "Test Patchy";
            
    alex = new_identity(alex_address, NULL, alex_userid, new_username);
    cout << "Timing is everything" << endl; 
    status = update_identity(session, alex);
    assert(status == PEP_STATUS_OK);
    assert(alex->fpr);
    assert(strcmp(alex->fpr, alex_fpr) == 0);
    assert(alex->username);
    assert(strcmp(alex->username, new_username) == 0);
    assert(alex->user_id);
    assert(strcmp(alex->user_id, alex_userid) == 0);
    assert(!alex->me); 
    assert(alex->comm_type == PEP_ct_OpenPGP_unconfirmed);
    assert(strcmp(alex->address, alex_address) == 0);

    cout << "PASS: update_identity() correctly retrieved extant record with matching address and id, and patched username" << endl << endl;
    free_identity(alex);

    cout << "****************************************************************************************" << endl;
    cout << "* II: 3. update_identity() - get identity with matching address and user_id only" << endl;
    cout << "****************************************************************************************" << endl << endl;    
        
    alex = new_identity(alex_address, NULL, alex_userid, NULL); 
    status = update_identity(session, alex);
    assert(status == PEP_STATUS_OK);
    assert(alex->fpr);
    assert(strcmp(alex->fpr, alex_fpr) == 0);
    assert(alex->username);
    assert(strcmp(alex->username, new_username) == 0);
    assert(alex->user_id);
    assert(strcmp(alex->user_id, alex_userid) == 0);
    assert(!alex->me); 
    assert(alex->comm_type == PEP_ct_OpenPGP_unconfirmed);
    assert(strcmp(alex->address, alex_address) == 0);

    cout << "PASS: update_identity() correctly retrieved extant record with matching address and id, and patched username" << endl << endl;
    free_identity(alex);

    cout << "****************************************************************************************" << endl;
    cout << "* II: 4. update_identity() - get identity with just address and username" << endl;
    cout << "****************************************************************************************" << endl << endl;    

    alex = new_identity(alex_address, NULL, NULL, new_username); 
    status = update_identity(session, alex);
    assert(status == PEP_STATUS_OK);
    assert(alex->fpr);
    assert(strcmp(alex->fpr, alex_fpr) == 0);
    assert(alex->username);
    assert(strcmp(alex->username, new_username) == 0);
    assert(alex->user_id);
    assert(strcmp(alex->user_id, alex_userid) == 0);
    assert(!alex->me); 
    assert(alex->comm_type == PEP_ct_OpenPGP_unconfirmed);
    assert(strcmp(alex->address, alex_address) == 0);

    cout << "PASS: update_identity() correctly retrieved extant record with matching address and username" << endl << endl;
    free_identity(alex);

    cout << "****************************************************************************************" << endl;
    cout << "* II: 5. update_identity() with just address " << endl;
    cout << "****************************************************************************************" << endl << endl;
    
    alex = new_identity(alex_address, NULL, NULL, NULL); 
    status = update_identity(session, alex);
    assert(status == PEP_STATUS_OK);
    assert(alex->fpr);
    assert(strcmp(alex->fpr, alex_fpr) == 0);
    assert(alex->username);
    assert(strcmp(alex->username, new_username) == 0);
    assert(alex->user_id);
    assert(strcmp(alex->user_id, alex_userid) == 0);
    assert(!alex->me); 
    assert(alex->comm_type == PEP_ct_OpenPGP_unconfirmed);
    assert(strcmp(alex->address, alex_address) == 0);

    cout << "PASS: update_identity() correctly retrieved extant record with just matching address. Retrieved previously patched username." << endl << endl;
    free_identity(alex);


    cout << "****************************************************************************************" << endl;
    cout << "* II: 6. update_identity() with just address on own identity (only case where this is legal)" << endl;
    cout << "****************************************************************************************" << endl << endl;
    
    pEp_identity* somebody = new_identity(uniqname, NULL, NULL, NULL); 
    status = update_identity(session, somebody);
    assert(status == PEP_STATUS_OK);
    myself(session, somebody);
    assert(somebody->fpr);
    assert(strcmp(somebody->fpr, new_fpr) == 0);
    assert(somebody->username);
    assert(strcmp(somebody->username, start_username) == 0);
    assert(somebody->user_id);
    assert(strcmp(somebody->user_id, default_own_id) == 0);
    assert(somebody->me); // true in this case, as it was an own identity
    assert(somebody->comm_type == PEP_ct_pEp);
    assert(strcmp(somebody->address, uniqname) == 0);
    
    cout << "PASS: update_identity() retrieved the right identity information given just an address";
    cout << endl << endl;

    free_identity(somebody);

    cout << "****************************************************************************************" << endl;
    cout << "* II: 7. update_identity() for address and user_id that don't exist" << endl;
    cout << "****************************************************************************************" << endl << endl;

    somebody = new_identity("nope@nope.nope", NULL, "some_user_id", NULL); 
    status = update_identity(session, somebody);
    assert(status == PEP_STATUS_OK);
    assert(!somebody->fpr);
    assert(somebody->comm_type == PEP_ct_key_not_found);
    
    cout << "PASS: update_identity() returns identity with no key and unknown comm type" << endl << endl;

    free_identity(somebody);
    
    cout << "****************************************************************************************" << endl;
    cout << "* II: 8. update_identity() for address and and username, but non-matching temp user_id" << endl;
    cout << "****************************************************************************************" << endl << endl;

    // 1. create identity
    const char* bella_address = "pep.test.bella@peptest.ch";
    const char* bella_fpr = "5631BF1357326A02AA470EEEB815EF7FA4516AAE";
    const char* bella_userid = "TOFU_pep.test.bella@peptest.ch"; // simulate temp ID
    const char* bella_username = "Annabella the Great";
    const string bella_pub_key = slurp("test_keys/pub/pep.test.bella-0xAF516AAE_pub.asc");
    
    statuspub = import_key(session, bella_pub_key.c_str(), bella_pub_key.length(), NULL);
    assert(statuspub == PEP_STATUS_OK);

    pEp_identity* bella = new_identity(bella_address, bella_fpr, bella_userid, bella_username);
    
    // 2. set identity
    status = set_identity(session, bella);
    assert(status == PEP_STATUS_OK);
    free_identity(bella);
    
    const char* not_my_userid = "Bad Company";
            
    bella = new_identity(bella_address, NULL, not_my_userid, bella_username); 
    status = update_identity(session, bella);
    assert(status == PEP_STATUS_OK);
    assert(bella->fpr);
    assert(strcmp(bella->fpr, bella_fpr) == 0);
    assert(bella->username);
    assert(strcmp(bella->username, bella_username) == 0);
    assert(bella->user_id);
    assert(strcmp(bella->user_id, not_my_userid) == 0); // ???
    assert(!bella->me); 
    assert(bella->comm_type == PEP_ct_OpenPGP_unconfirmed);
    assert(strcmp(bella->address, bella_address) == 0);

    cout << "PASS: update_identity() correctly retrieved extant record with matching address and username; temp user_id in DB patched" << endl << endl;
    free_identity(bella);

    cout << "****************************************************************************************" << endl;
    cout << "* II: 9. update_identity() for address, username, and user_id, but no matching record" << endl;
    cout << "****************************************************************************************" << endl << endl;
    
    const char* rando_name = "Pickley BoofBoof";
    const char* rando_userid = "Boofy";
    const char* rando_address = "boof@pickles.org";
    somebody = new_identity(rando_address, NULL, rando_userid, rando_name);
    status = update_identity(session, somebody);

    assert(status == PEP_STATUS_OK);
    assert(!somebody->fpr || somebody->fpr[0] == '\0');
    assert(somebody->username);
    assert(strcmp(somebody->username, rando_name) == 0);
    assert(somebody->user_id);
    assert(strcmp(somebody->user_id, rando_userid) == 0); // ???
    assert(!somebody->me); 
    assert(somebody->comm_type == PEP_ct_key_not_found);
    assert(strcmp(somebody->address, rando_address) == 0);

    cout << "PASS: update_identity() correctly created record with no key" << endl << endl;
    free_identity(somebody);
    
    cout << "****************************************************************************************" << endl;
    cout << "* II: 10. update_identity() for address, username, but no matching record" << endl;
    cout << "****************************************************************************************" << endl << endl;

    const char* rando2_name = "Pickles BoofyBoof";
    const char* rando2_address = "boof2@pickles.org";
    somebody = new_identity(rando2_address, NULL, NULL, rando2_name);
    status = update_identity(session, somebody);
    const char* expected_rando2_userid = "TOFU_boof2@pickles.org";

    assert(status == PEP_STATUS_OK);
    assert(!somebody->fpr || somebody->fpr[0] == '\0');
    assert(somebody->username);
    assert(strcmp(somebody->username, rando2_name) == 0);
    assert(somebody->user_id);
    assert(strcmp(somebody->user_id, expected_rando2_userid) == 0); // ???
    assert(!somebody->me); 
    assert(somebody->comm_type == PEP_ct_key_not_found);
    assert(strcmp(somebody->address, rando2_address) == 0);

    cout << "PASS: update_identity() correctly created record with no key" << endl << endl;
    free_identity(somebody);

    cout << "****************************************************************************************" << endl;
    cout << "* II: 11. update_identity() for address only, but multiple matching records" << endl;
    cout << "****************************************************************************************" << endl << endl;

    const char* bella_id_2 = "Bella2";
    bella = new_identity(bella_address, NULL, bella_id_2, bella_username);
    
    // 2. set identity
    status = set_identity(session, bella);
    assert(status == PEP_STATUS_OK);
    free_identity(bella);
                
    bella = new_identity(bella_address, NULL, NULL, NULL); 
    status = update_identity(session, bella);
    assert(status == PEP_STATUS_OK);

//    cout << "PASS: update_identity() correctly failed with no matching records (too little info)" << endl << endl;
    
    cout << "****************************************************************************************" << endl;
    cout << "* III: key election " << endl;
    cout << "****************************************************************************************" << endl << endl;

    cout << "****************************************************************************************" << endl;
    cout << "* III: 1. key election: get identity for user with expired key" << endl;
    cout << "****************************************************************************************" << endl << endl;

    // 1. create identity
    const char* bernd_address = "bernd.das.brot@darthmama.org";
    const char* bernd_fpr = "F8CE0F7E24EB190A2FCBFD38D4B088A7CAFAA422";
    const char* bernd_userid = "BERND_ID"; // simulate temp ID
    const char* bernd_username = "Bernd das Brot der Ultimative Testkandidat";
    const string bernd_pub_key = slurp("test_keys/pub/bernd.das.brot-0xCAFAA422_pub.asc");
    
    statuspub = import_key(session, bernd_pub_key.c_str(), bernd_pub_key.length(), NULL);
    assert(statuspub == PEP_STATUS_OK);

    pEp_identity* bernd = new_identity(bernd_address, bernd_fpr, bernd_userid, bernd_username);
    
    // 2. set identity
    status = set_identity(session, bernd);
    assert(status == PEP_STATUS_OK);
    free_identity(bernd);
                
    bernd = new_identity(bernd_address, NULL, bernd_userid, bernd_username); 
    status = update_identity(session, bernd);
    assert(status != PEP_STATUS_OK);
    assert(!bernd->fpr || bernd->fpr[0] == '\0');
    assert(bernd->username);
    assert(strcmp(bernd->username, bernd_username) == 0);
    assert(bernd->user_id);
    assert(strcmp(bernd->user_id, bernd_userid) == 0); // ???
    assert(!bernd->me); 
    assert(bernd->comm_type == PEP_ct_key_expired);
    assert(strcmp(bernd->address, bernd_address) == 0);

    cout << "PASS: update_identity() correctly rejected expired key with PEP_KEY_UNSUITABLE and PEP_ct_key_expired" << endl << endl;
    free_identity(bernd);


    cout << "****************************************************************************************" << endl;
    cout << "* III: 2. key election: get identity for user with only revoked or mistrusted keys " << endl;
    cout << "****************************************************************************************" << endl << endl;

    // Create id with no key
    cout << "Creating new id with no key for : ";
    char *uniqname_10000 = strdup("AAAAtestuser@testdomain.org");
    srandom(time(NULL));
    for(int i=0; i < 4;i++)
        uniqname_10000[i] += random() & 0xf;
    
    cout << uniqname_10000 << "\n";

    char* revoke_uuid = get_new_uuid();

    pEp_identity * revokemaster_3000 = new_identity(uniqname_10000, NULL, revoke_uuid, start_username);
    
    cout << "Generate three keys for "  << uniqname_10000 << " who has user_id " << revoke_uuid << endl; 

    char* revoke_fpr_arr[3];
    
    status = generate_keypair(session, revokemaster_3000);
    assert(status == PEP_STATUS_OK && revokemaster_3000->fpr);
    revoke_fpr_arr[0] = strdup(revokemaster_3000->fpr);
    free(revokemaster_3000->fpr);
    revokemaster_3000->fpr = NULL;
    
    status = generate_keypair(session, revokemaster_3000);
    assert(status == PEP_STATUS_OK && revokemaster_3000->fpr);
    revoke_fpr_arr[1] = strdup(revokemaster_3000->fpr);
    free(revokemaster_3000->fpr);
    revokemaster_3000->fpr = NULL;
    
    status = generate_keypair(session, revokemaster_3000);
    assert(status == PEP_STATUS_OK && revokemaster_3000->fpr);
    revoke_fpr_arr[2] = strdup(revokemaster_3000->fpr);
    free(revokemaster_3000->fpr);
    revokemaster_3000->fpr = NULL;
    
    cout << "Trust "  << revoke_fpr_arr[2] << " (default for identity) and " << revoke_fpr_arr[0] << endl;
    
    free(revokemaster_3000->fpr);
    revokemaster_3000->fpr = strdup(revoke_fpr_arr[2]);
    status = trust_personal_key(session, revokemaster_3000);
    assert(status == PEP_STATUS_OK);
    status = get_trust(session, revokemaster_3000);
    assert(status == PEP_STATUS_OK);
    assert(revokemaster_3000->comm_type & PEP_ct_confirmed);

    free(revokemaster_3000->fpr);
    revokemaster_3000->fpr = strdup(revoke_fpr_arr[0]);
    status = trust_personal_key(session, revokemaster_3000);
    assert(status == PEP_STATUS_OK);
    status = get_trust(session, revokemaster_3000);
    assert(status == PEP_STATUS_OK);
    assert(revokemaster_3000->comm_type & PEP_ct_confirmed);
    
    status = update_identity(session, revokemaster_3000);
    assert(status == PEP_STATUS_OK);
    assert(revokemaster_3000->fpr);
    assert(strcmp(revokemaster_3000->fpr, revoke_fpr_arr[2]) == 0);
    assert(revokemaster_3000->comm_type & PEP_ct_confirmed);

    cout << "update_identity returns the correct identity default." << endl;
    
    cout << "Ok, now... we revoke the default..." << endl;
    
    cout << "Revoking " << revoke_fpr_arr[2] << endl;

    status = revoke_key(session, revoke_fpr_arr[2], "This little pubkey went to market");
    assert (status == PEP_STATUS_OK);

    bool is_revoked;
    status = key_revoked(session, revokemaster_3000->fpr, &is_revoked);    
    assert(status == PEP_STATUS_OK);
    assert(is_revoked);

    cout << "Success revoking " << revoke_fpr_arr[2] << "!!! get_trust for this fpr gives us " << revokemaster_3000->comm_type << endl;
    
    cout << "Now see if update_identity gives us " << revoke_fpr_arr[0] << ", the only trusted key left." << endl;
    status = update_identity(session, revokemaster_3000);
    assert(status == PEP_STATUS_OK);
    assert(revokemaster_3000->fpr);
    assert(strcmp(revokemaster_3000->fpr, revoke_fpr_arr[0]) == 0);
    assert(revokemaster_3000->comm_type & PEP_ct_confirmed);    
    
    cout << "Success! So let's mistrust it, because seriously, that key was so uncool." << endl;
    
    status = key_mistrusted(session, revokemaster_3000);
    assert(status == PEP_STATUS_OK);

    status = get_trust(session, revokemaster_3000);
    assert(status == PEP_STATUS_OK);
    assert(revokemaster_3000->comm_type == PEP_ct_mistrusted);
    
    cout << "Success! get_trust for this fpr gives us " << revokemaster_3000->comm_type << endl;

    cout << "The only fpr left is an untrusted one - let's make sure this is what we get from update_identity." << endl;

    status = update_identity(session, revokemaster_3000);
    assert(status == PEP_STATUS_OK);
    assert(revokemaster_3000->fpr);
    assert(strcmp(revokemaster_3000->fpr, revoke_fpr_arr[1]) == 0);
    assert(!(revokemaster_3000->comm_type & PEP_ct_confirmed));    

    cout << "Success! We got " << revoke_fpr_arr[1] << "as the fpr with comm_type " << revokemaster_3000->comm_type << endl;
    
    cout << "But, you know... let's revoke that one too and see what update_identity gives us." << endl;

    status = revoke_key(session, revoke_fpr_arr[1], "Because it's more fun to revoke ALL of someone's keys");
    assert (status == PEP_STATUS_OK);

    status = key_revoked(session, revokemaster_3000->fpr, &is_revoked);    
    assert(status == PEP_STATUS_OK);
    assert(is_revoked);
    
    cout << "Success! get_trust for this fpr gives us " << revokemaster_3000->comm_type << endl;

    cout << "Call update_identity - we expect nothing, plus an error comm type." << endl;

    status = update_identity(session, revokemaster_3000);
    assert(status != PEP_STATUS_OK);
    assert(!revokemaster_3000->fpr);
    assert(revokemaster_3000->username);
    assert(strcmp(revokemaster_3000->user_id, revoke_uuid) == 0);
    assert(revokemaster_3000->comm_type == PEP_ct_key_not_found);
    cout << "Success! No key found. The comm_status error was " << revokemaster_3000->comm_type << "and the return status was " << tl_status_string(status) << endl;

    free_identity(revokemaster_3000);

    cout << "****************************************************************************************" << endl;
    cout << "* III: 100000000. key election: more to come " << endl;
    cout << "****************************************************************************************" << endl << endl;

    return 0;
}
