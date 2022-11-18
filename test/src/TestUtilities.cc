#include "pEpEngine_test.h"
#include "pEpEngine.h"
#include "pEp_internal.h"
#include "pEp_internal.h"
#include "message_api.h"
#include "TestUtilities.h"
#include "TestConstants.h"
#include "mime.h"
#include "message_api.h"
#include "keymanagement.h"

#include <fstream>
#include <algorithm>
#include <sstream>
#include <iostream>
#include <stdexcept>
#include <algorithm>
#include <vector>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <ftw.h>
#include <fstream>
#include <iostream>

using namespace std;

std::string _main_test_home_dir;

#define BUF_MAX_PATHLEN 4097


const TestUtilsPreset::IdentityInfo TestUtilsPreset::presets[]     = {
                TestUtilsPreset::IdentityInfo("Alice Spivak Hyatt", "ALICE", "pep.test.alice@pep-project.org", "pep-test-alice-0x6FF00E97", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97"),
                TestUtilsPreset::IdentityInfo("Apple of my Computer", "APPLE", "pep.test.apple@pep-project.org", "pep-test-apple-0x1CCBC7D7", "3D8D9423D03DDF61B60161150313D94A1CCBC7D7"),
                TestUtilsPreset::IdentityInfo("Bob Dog", "BOB", "pep.test.bob@pep-project.org", "pep-test-bob-0xC9C2EE39", "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39"),
                TestUtilsPreset::IdentityInfo("Bob Dog", "BOB", "pep.test.bob@pep-project.org", "pep-test-bob-0x9667F61D", "C47ADE6207C7C3098C6E83D9FF3D3F669667F61D"),
                TestUtilsPreset::IdentityInfo("Carol Burnett", "CAROL", "pep-test-carol@pep-project.org", "pep-test-carol-0x42A85A42", "8DD4F5827B45839E9ACCA94687BDDFFB42A85A42"),
                TestUtilsPreset::IdentityInfo("The Hoff", "DAVE", "pep-test-dave@pep-project.org", "pep-test-dave-0xBB5BCCF6", "E8AC9779A2D13A15D8D55C84B049F489BB5BCCF6"),
                TestUtilsPreset::IdentityInfo("Erin Ireland", "ERIN", "pep-test-erin@pep-project.org", "pep-test-erin-0x9F8D7CBA", "1B0E197E8AE66277B8A024B9AEA69F509F8D7CBA"),
                TestUtilsPreset::IdentityInfo("Frank N. Furter", "FRANK", "pep-test-frank@pep-project.org", "pep-test-frank-0x9A7FC670", "B022B74476D8A8E1F01E55FBAB6972569A7FC670"),  // currently expired
                TestUtilsPreset::IdentityInfo("Gabrielle Gonzales", "GABI", "pep-test-gabrielle@pep-project.org", "pep-test-gabrielle-0xE203586C", "906C9B8349954E82C5623C3C8C541BD4E203586C"),
                TestUtilsPreset::IdentityInfo("John Denver", "JOHN", "pep.test.john@pep-project.org", "pep-test-john-0x70DCF575", "AA2E4BEB93E5FE33DEFD8BE1135CD6D170DCF575"),
                TestUtilsPreset::IdentityInfo("Alex Braithwaite", "ALEX", "pep.test.alexander@peptest.ch", "pep.test.alexander-0x26B54E4E", "3AD9F60FAEB22675DB873A1362D6981326B54E4E"),
                TestUtilsPreset::IdentityInfo("Alex Braithwaite", "ALEX", "pep.test.alexander0@darthmama.org", "pep.test.alexander0-0x3B7302DB", "F4598A17D4690EB3B5B0F6A344F04E963B7302DB"),
                TestUtilsPreset::IdentityInfo("Alex Braithwaite", "ALEX", "pep.test.alexander1@darthmama.org", "pep.test.alexander1-0x541260F6", "59AF4C51492283522F6904531C09730A541260F6"),
                TestUtilsPreset::IdentityInfo("Alex Braithwaite", "ALEX", "pep.test.alexander2@darthmama.org", "pep.test.alexander2-0xA6512F30", "46A994F19077C05610870273C4B8AB0BA6512F30"),
                TestUtilsPreset::IdentityInfo("Alex Braithwaite", "ALEX", "pep.test.alexander3@darthmama.org", "pep.test.alexander3-0x724B3975", "5F7076BBD92E14EA49F0DF7C2CE49419724B3975"),
                TestUtilsPreset::IdentityInfo("Alex Braithwaite", "ALEX", "pep.test.alexander4@darthmama.org", "pep.test.alexander4-0x844B9DCF", "E95FFF95B8E2FDD4A12C3374395F1485844B9DCF"),
                TestUtilsPreset::IdentityInfo("Alex Braithwaite", "ALEX", "pep.test.alexander5@darthmama.org", "pep.test.alexander5-0x0773CD29", "58BCC2BF2AE1E3C4FBEAB89AD7838ACA0773CD29"),
                TestUtilsPreset::IdentityInfo("Alex Braithwaite", "ALEX", "pep.test.alexander6@darthmama.org", "pep.test.alexander6-0x0019697D", "74D79B4496E289BD8A71B70BA8E2C4530019697D"),
                TestUtilsPreset::IdentityInfo("Alex Braithwaite", "ALEX", "pep.test.alexander6@darthmama.org", "pep.test.alexander6-0x503B14D8", "2E21325D202A44BFD9C607FCF095B202503B14D8"),
                TestUtilsPreset::IdentityInfo("Alex Braithwaite", "ALEX", "pep.test.alexander6@darthmama.org", "pep.test.alexander6-0xA216E95A", "3C1E713D8519D7F907E3142D179EAA24A216E95A"),
                TestUtilsPreset::IdentityInfo("Alex Braithwaite", "ALEX", "pep.test.alexander6@darthmama.org", "pep.test.alexander6-0xBDA17020", "B4CE2F6947B6947C500F0687AEFDE530BDA17020"),
                TestUtilsPreset::IdentityInfo("Bella Cat", "BELLA", "pep.test.bella@peptest.ch", "pep.test.bella-0xAF516AAE", "5631BF1357326A02AA470EEEB815EF7FA4516AAE"),
                TestUtilsPreset::IdentityInfo("Fenris Leto Hawke", "FENRIS", "pep.test.fenris@thisstilldoesntwork.lu", "pep.test.fenris-0x4F3D2900", "0969FA229DF21C832A64A04711B1B9804F3D2900"),
                TestUtilsPreset::IdentityInfo("Cullen Rutherford", "CULLEN", "sercullen-test@darthmama.org", "sercullen-0x3CEAADED4", "1C9666D8B3E28F4AA3847DA89A6E75E3CEAADED4"),  // NB expired on purpose
                TestUtilsPreset::IdentityInfo("Inquisitor Claire Trevelyan", "INQUISITOR", "inquisitor@darthmama.org", "inquisitor-0xA4728718_renewed", "8E8D2381AE066ABE1FEE509821BA977CA4728718"),
                TestUtilsPreset::IdentityInfo("Bernd das Brot", "BERNDI", "bernd.das.brot@darthmama.org", "bernd.das.brot-0xCAFAA422", "F8CE0F7E24EB190A2FCBFD38D4B088A7CAFAA422"),
                TestUtilsPreset::IdentityInfo("Sylvia Plath", "SYLVIA", "sylvia@darthmama.org", "sylvia-0x585A6780", "0C0F053EED87058C7330A11F10B89D31585A6780"),
                TestUtilsPreset::IdentityInfo("Sylvia Plath", "SYLVIA", "sylvia@darthmama.org", "sylvia-0x2E5A78A9", "3FB4EB6F00E96E163FB05C0374B8F0832E5A78A9")
    };


bool is_pEpmsg(const message *msg)
{
    for (stringpair_list_t *i = msg->opt_fields; i && i->value ; i=i->next) {
        if (strcasecmp(i->value->key, "X-pEp-Version") == 0)
            return true;
    }
    return false;
}

// Lazy:
// https://stackoverflow.com/questions/440133/how-do-i-create-a-random-alpha-numeric-string-in-c
std::string random_string( size_t length )
{
    auto randchar = []() -> char
    {
        const char charset[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
        const size_t max_index = (sizeof(charset) - 1);
        return charset[ rand() % max_index ];
    };
    std::string str(length,0);
    std::generate_n( str.begin(), length, randchar );
    return str;
}

std::string get_main_test_home_dir() {
    char buf[BUF_MAX_PATHLEN];// Linux max path size...

    if (_main_test_home_dir.empty()) {
        string curr_wd = getcwd(buf, BUF_MAX_PATHLEN);

        if (curr_wd.empty())
            throw std::runtime_error("Error grabbing current working directory");

        _main_test_home_dir = curr_wd + "/pEp_test_home";
    }
    return _main_test_home_dir;
}

PEP_STATUS read_file_and_import_key(PEP_SESSION session, const char* fname) {
    const std::string key = slurp(fname);
    PEP_STATUS status = (key.empty() ? PEP_KEY_NOT_FOUND : PEP_STATUS_OK);
    if (status == PEP_STATUS_OK)
        status = import_key(session, key.c_str(), key.size(), NULL);
    return status;
}

PEP_STATUS set_up_ident_from_scratch(PEP_SESSION session,
                                     const char* key_fname,
                                     const char* address,
                                     const char* fpr,
                                     const char* user_id,
                                     const char* username,
                                     pEp_identity** ret_ident,
                                     bool is_priv) {
    PEP_STATUS status = read_file_and_import_key(session,key_fname);
    if (status != PEP_KEY_IMPORTED)
        return status;
    else
        status = PEP_STATUS_OK;

    pEp_identity* ident = new_identity(address, fpr, user_id, username);
    if (is_priv && fpr) {
        status = set_own_key(session, ident, fpr);
        if (status == PEP_STATUS_OK)
            status = myself(session, ident);
    }
    else {
        if (!EMPTYSTR(fpr)) {
            status = set_fpr_preserve_ident(session, ident, fpr, false);
            if (status != PEP_STATUS_OK)
                goto pep_free;
        }        
        status = update_identity(session, ident);
    }    
    if (status != PEP_STATUS_OK)
        goto pep_free;

    if (!ident || !ident->fpr) {
        status = PEP_CANNOT_FIND_IDENTITY;
        goto pep_free;
    }

    if (ret_ident)
        *ret_ident = ident;

pep_free:
    if (!ret_ident)
        free_identity(ident);
    return status;
}


bool file_exists(std::string filename) {
    struct stat buffer;
    return (stat(filename.c_str(), &buffer) == 0);
}

char* str_to_lower(const char* str) {
    if (!str)
        return NULL;
    int str_len = strlen(str);
    if (str_len == 0)
        return strdup("");
    int i;

    char* retval = (char*) calloc(1, str_len + 1);
    for (i = 0; i < str_len; i++) {
        retval[i] = tolower(str[i]);
    }
    return retval;
}

// Because annoyed
bool _streq(const char* str1, const char* str2) {
    if (!str1) {
        if (str2)
            return false;
        return true;
    }
    if (!str2)
        return false;

    return (strcmp(str1, str2) == 0);
}

bool _strceq(const char* str1, const char* str2) {
    char* str1_dup = str_to_lower(str1);
    char* str2_dup = str_to_lower(str2);

    bool retval = _streq(str_to_lower(str1_dup), str_to_lower(str2_dup));
    free(str1_dup);
    free(str2_dup);
    return retval;
}

void test_init() {
    unlink ("../test_home/.pEp_management.db");
    unlink ("../test_home/.pEp_management.db-shm");
    unlink ("../test_home/.pEp_management.db-wal");
}

std::string slurp(const std::string& filename)
{
	std::ifstream input(filename.c_str());
	if(!input)
	{
		throw std::runtime_error("Cannot read file \"" + filename + "\"! ");
	}

	std::stringstream sstr;
	sstr << input.rdbuf();
	return sstr.str();
}

void dump_out(const char* filename, const char* outdata)
{
	std::ofstream outfile(filename);
	if(!outfile)
	{
		throw std::runtime_error("Cannot open output file!");
	}

	outfile << outdata;
    outfile.close();
}

char* get_new_uuid() {
    char* new_uuid = (char*)calloc(37, 1);
    pEpUUID uuid;
    uuid_generate_random(uuid);
    uuid_unparse_upper(uuid, new_uuid);
    return new_uuid;
}

const char* tl_status_string(PEP_STATUS status) {
    switch (status) {
        case PEP_STATUS_OK:
            return "PEP_STATUS_OK";
        case PEP_INIT_CANNOT_LOAD_CRYPTO_LIB:
            return "PEP_INIT_CANNOT_LOAD_CRYPTO_LIB";
        case PEP_INIT_CRYPTO_LIB_INIT_FAILED:
            return "PEP_INIT_CRYPTO_LIB_INIT_FAILED";
        case PEP_INIT_NO_CRYPTO_HOME:
            return "PEP_INIT_NO_CRYPTO_HOME";
        // case PEP_INIT_NETPGP_INIT_FAILED:
        //     return "PEP_INIT_NETPGP_INIT_FAILED";
        case PEP_INIT_SQLITE3_WITHOUT_MUTEX:
            return "PEP_INIT_SQLITE3_WITHOUT_MUTEX";
        case PEP_INIT_CANNOT_OPEN_DB:
            return "PEP_INIT_CANNOT_OPEN_DB";
        case PEP_INIT_CANNOT_OPEN_SYSTEM_DB:
            return "PEP_INIT_CANNOT_OPEN_SYSTEM_DB";
        case PEP_KEY_NOT_FOUND:
            return "PEP_KEY_NOT_FOUND";
        case PEP_KEY_HAS_AMBIG_NAME:
            return "PEP_KEY_HAS_AMBIG_NAME";
        case PEP_GET_KEY_FAILED:
            return "PEP_GET_KEY_FAILED";
        case PEP_CANNOT_EXPORT_KEY:
            return "PEP_CANNOT_EXPORT_KEY";
        case PEP_CANNOT_EDIT_KEY:
            return "PEP_CANNOT_EDIT_KEY";
        case PEP_CANNOT_DELETE_KEY:
            return "PEP_CANNOT_DELETE_KEY";
        case PEP_CANNOT_FIND_IDENTITY:
            return "PEP_CANNOT_FIND_IDENTITY";
        case PEP_CANNOT_SET_PERSON:
            return "PEP_CANNOT_SET_PERSON";
        case PEP_CANNOT_SET_PGP_KEYPAIR:
            return "PEP_CANNOT_SET_PGP_KEYPAIR";
        case PEP_CANNOT_SET_PEP_VERSION:
            return "PEP_CANNOT_SET_PEP_VERSION";
        case PEP_CANNOT_SET_IDENTITY:
            return "PEP_CANNOT_SET_IDENTITY";
        case PEP_CANNOT_SET_TRUST:
            return "PEP_CANNOT_SET_TRUST";
        case PEP_KEY_BLACKLISTED:
            return "PEP_KEY_BLACKLISTED";
        case PEP_UNENCRYPTED:
            return "PEP_UNENCRYPTED";
        case PEP_VERIFIED:
            return "PEP_VERIFIED";
        case PEP_DECRYPTED:
            return "PEP_DECRYPTED";
        case PEP_DECRYPTED_AND_VERIFIED:
            return "PEP_DECRYPTED_AND_VERIFIED";
        case PEP_DECRYPT_WRONG_FORMAT:
            return "PEP_DECRYPT_WRONG_FORMAT";
        case PEP_DECRYPT_NO_KEY:
            return "PEP_DECRYPT_NO_KEY";
        case PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH:
            return "PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH";
//        case PEP_DECRYPTED_BUT_UNSIGNED:
//            return "PEP_DECRYPTED_BUT_UNSIGNED";
//        case PEP_DECRYPT_MODIFICATION_DETECTED:
//            return "PEP_DECRYPT_MODIFICATION_DETECTED";
//        case PEP_DECRYPT_NO_KEY_FOR_SIGNER:
//            return "PEP_DECRYPT_NO_KEY_FOR_SIGNER";
        case PEP_VERIFY_NO_KEY:
            return "PEP_VERIFY_NO_KEY";
        case PEP_VERIFIED_AND_TRUSTED:
            return "PEP_VERIFIED_AND_TRUSTED";
        case PEP_CANNOT_DECRYPT_UNKNOWN:
            return "PEP_CANNOT_DECRYPT_UNKNOWN";
        case PEP_TRUSTWORD_NOT_FOUND:
            return "PEP_TRUSTWORD_NOT_FOUND";
        case PEP_TRUSTWORDS_FPR_WRONG_LENGTH:
            return "PEP_TRUSTWORDS_FPR_WRONG_LENGTH";
        case PEP_CANNOT_CREATE_KEY:
            return "PEP_CANNOT_CREATE_KEY";
        case PEP_CANNOT_SEND_KEY:
            return "PEP_CANNOT_SEND_KEY";
        case PEP_PHRASE_NOT_FOUND:
            return "PEP_PHRASE_NOT_FOUND";
        case PEP_SEND_FUNCTION_NOT_REGISTERED:
            return "PEP_SEND_FUNCTION_NOT_REGISTERED";
        case PEP_CONTRAINTS_VIOLATED:
            return "PEP_CONTRAINTS_VIOLATED";
        case PEP_CANNOT_ENCODE:
            return "PEP_CANNOT_ENCODE";
        case PEP_SYNC_NO_NOTIFY_CALLBACK:
            return "PEP_SYNC_NO_NOTIFY_CALLBACK";
        case PEP_SYNC_ILLEGAL_MESSAGE:
            return "PEP_SYNC_ILLEGAL_MESSAGE";
        case PEP_SYNC_NO_INJECT_CALLBACK:
            return "PEP_SYNC_NO_INJECT_CALLBACK";
        case PEP_CANNOT_INCREASE_SEQUENCE:
            return "PEP_CANNOT_INCREASE_SEQUENCE";
        case PEP_STATEMACHINE_ERROR:
            return "PEP_STATEMACHINE_ERROR";
        case PEP_NO_TRUST:
            return "PEP_NO_TRUST";
        case PEP_STATEMACHINE_INVALID_STATE:
            return "PEP_STATEMACHINE_INVALID_STATE";
        case PEP_STATEMACHINE_INVALID_EVENT:
            return "PEP_STATEMACHINE_INVALID_EVENT";
        case PEP_STATEMACHINE_INVALID_CONDITION:
            return "PEP_STATEMACHINE_INVALID_CONDITION";
        case PEP_STATEMACHINE_INVALID_ACTION:
            return "PEP_STATEMACHINE_INVALID_ACTION";
        case PEP_STATEMACHINE_INHIBITED_EVENT:
            return "PEP_STATEMACHINE_INHIBITED_EVENT";
        case PEP_COMMIT_FAILED:
            return "PEP_COMMIT_FAILED";
        case PEP_MESSAGE_CONSUME:
            return "PEP_MESSAGE_CONSUME";
        case PEP_MESSAGE_IGNORE:
            return "PEP_MESSAGE_IGNORE";
        case PEP_RECORD_NOT_FOUND:
            return "PEP_RECORD_NOT_FOUND";
        case PEP_CANNOT_CREATE_TEMP_FILE:
            return "PEP_CANNOT_CREATE_TEMP_FILE";
        case PEP_ILLEGAL_VALUE:
            return "PEP_ILLEGAL_VALUE";
        case PEP_BUFFER_TOO_SMALL:
            return "PEP_BUFFER_TOO_SMALL";
        case PEP_OUT_OF_MEMORY:
            return "PEP_OUT_OF_MEMORY";
        case PEP_UNKNOWN_ERROR:
            return "PEP_UNKNOWN_ERROR";
        default:

            return "PEP_STATUS_OMGWTFBBQ - This means you're using a status the test lib doesn't know about!";
    }
}
const char* tl_rating_string(PEP_rating rating) {
    switch (rating) {
        case PEP_rating_undefined:
            return "PEP_rating_undefined";
        case PEP_rating_cannot_decrypt:
            return "PEP_rating_cannot_decrypt";
        case PEP_rating_have_no_key:
            return "PEP_rating_have_no_key";
        case PEP_rating_unencrypted:
            return "PEP_rating_unencrypted";
        case PEP_rating_media_key_protected:
            return "PEP_rating_media_key_protected";
        case PEP_rating_unreliable:
            return "PEP_rating_unreliable";
        case PEP_rating_reliable:
            return "PEP_rating_reliable";
        case PEP_rating_trusted:
            return "PEP_rating_trusted";
        case PEP_rating_trusted_and_anonymized:
            return "PEP_rating_trusted_and_anonymized";
        case PEP_rating_fully_anonymous:
            return "PEP_rating_fully_anonymous";
        case PEP_rating_mistrust:
            return "PEP_rating_mistrust";
        case PEP_rating_b0rken:
            return "PEP_rating_b0rken";
        case PEP_rating_under_attack:
            return "PEP_rating_under_attack";
        default:
            return "PEP_rating_OMGWTFBBQ - in other words, INVALID RATING VALUE!!!\n\nSomething bad is going on here, or a new rating value has been added to the enum and not the test function.";
    }
}

const char* tl_ct_string(PEP_comm_type ct) {
    switch (ct) {
        case PEP_ct_unknown:
            return "PEP_ct_unknown";
        case PEP_ct_no_encryption:
            return "PEP_ct_no_encryption";
        case PEP_ct_no_encrypted_channel:
            return "PEP_ct_no_encrypted_channel";
        case PEP_ct_key_not_found:
            return "PEP_ct_key_not_found";
        case PEP_ct_key_expired:
            return "PEP_ct_key_expired";
        case PEP_ct_key_revoked:
            return "PEP_ct_key_revoked";
        case PEP_ct_key_b0rken:
            return "PEP_ct_key_b0rken";
        case PEP_ct_my_key_not_included:
            return "PEP_ct_my_key_not_included";
        case PEP_ct_security_by_obscurity:
            return "PEP_ct_security_by_obscurity";
        case PEP_ct_b0rken_crypto:
            return "PEP_ct_b0rken_crypto";
        case PEP_ct_key_too_short:
            return "PEP_ct_key_too_short";
        case PEP_ct_compromised:
            return "PEP_ct_compromised";
        case PEP_ct_mistrusted:
            return "PEP_ct_mistrusted";
        case PEP_ct_unconfirmed_encryption:
            return "PEP_ct_unconfirmed_encryption";
        case PEP_ct_OpenPGP_weak_unconfirmed:
            return "PEP_ct_OpenPGP_weak_unconfirmed";
        case PEP_ct_to_be_checked:
            return "PEP_ct_to_be_checked";
        case PEP_ct_SMIME_unconfirmed:
            return "PEP_ct_SMIME_unconfirmed";
        case PEP_ct_CMS_unconfirmed:
            return "PEP_ct_CMS_unconfirmed";
        case PEP_ct_strong_but_unconfirmed:
            return "PEP_ct_strong_but_unconfirmed";
        case PEP_ct_OpenPGP_unconfirmed:
            return "PEP_ct_OpenPGP_unconfirmed";
        case PEP_ct_OTR_unconfirmed:
            return "PEP_ct_OTR_unconfirmed";
        case PEP_ct_unconfirmed_enc_anon:
            return "PEP_ct_unconfirmed_enc_anon";
        case PEP_ct_pEp_unconfirmed:
            return "PEP_ct_pEp_unconfirmed";
        case PEP_ct_confirmed:
            return "PEP_ct_pEp_confirmed";
        case PEP_ct_confirmed_encryption:
            return "PEP_ct_confirmed_encryption";
        case PEP_ct_OpenPGP_weak:
            return "PEP_ct_OpenPGP_weak";
        case PEP_ct_to_be_checked_confirmed:
            return "PEP_ct_to_be_checked_confirmed";
        case PEP_ct_SMIME:
            return "PEP_ct_SMIME";
        case PEP_ct_CMS:
            return "PEP_ct_CMS";
        case PEP_ct_strong_encryption:
            return "PEP_ct_strong_encryption";
        case PEP_ct_OpenPGP:
            return "PEP_ct_OpenPGP";
        case PEP_ct_OTR:
            return "PEP_ct_OTR";
        case PEP_ct_confirmed_enc_anon:
            return "PEP_ct_confirmed_enc_anon";
        case PEP_ct_pEp:
            return "PEP_ct_pEp";
        default:
            return "PEP_ct_OMGWTFBBQ\n\nIn other words, comm type is invalid. Either something's corrupt or a new ct value has been added to the enum but not to the test function.";
    }
}

std::string tl_ident_flags_String(identity_flags_t fl) {
    std::string retval;
    if (fl & PEP_idf_not_for_sync)   // don't use this identity for sync
        retval += " PEP_idf_not_for_sync";
    if (fl & PEP_idf_list)           // identity of list of persons
        retval += " PEP_idf_list";
    if (fl & PEP_idf_devicegroup)
        retval += "PEP_idf_devicegroup";
    if (retval.empty())
        return std::string("PEP_idf_OMGWTFBBQ");
    return retval;
}
bool slurp_and_import_key(PEP_SESSION session, const char* key_filename) {
    std::string keyfile = slurp(key_filename);
    if (import_key(session, keyfile.c_str(), keyfile.size(), NULL) != PEP_TEST_KEY_IMPORT_SUCCESS)
        return false;
    return true;
}

bool slurp_message_and_import_key(PEP_SESSION session, const char* message_fname, std::string& message, const char* key_filename) {
    bool ok = true;
    message = slurp(message_fname);
    if (key_filename)
        ok = slurp_and_import_key(session, key_filename);
    return ok;
}

message* slurp_message_file_into_struct(std::string infile, PEP_msg_direction direction) {
    message* retval = NULL;
    string msg_txt = slurp(infile);
    PEP_STATUS status = mime_decode_message(msg_txt.c_str(), msg_txt.size(), &retval, NULL);
    if (status != PEP_STATUS_OK) {
        free(retval);
        retval = NULL;
    }
    if (retval)
        retval->dir = direction;
    return retval;
}

char* message_to_str(message* msg) {
    char* retval = NULL;
    mime_encode_message(msg, false, &retval, false);
    return retval;
}

message* string_to_msg(string infile) {
    message* out_msg = NULL;
    mime_decode_message(infile.c_str(), infile.size(), &out_msg, NULL);
    return out_msg;
}

PEP_STATUS vanilla_encrypt_and_write_to_file(PEP_SESSION session, message* msg, const char* filename, PEP_encrypt_flags_t flags) {
    if (!session || !msg || !filename)
        return PEP_ILLEGAL_VALUE;
    message* enc_msg = NULL;
    char *msg_str = NULL;
    PEP_STATUS status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, flags);
    if (status != PEP_UNENCRYPTED) {
        if (status != PEP_STATUS_OK)
            return status;
        if (!enc_msg)
            return PEP_UNKNOWN_ERROR;
        msg_str = message_to_str(enc_msg);
        if (!msg_str)
            return PEP_UNKNOWN_ERROR;
    }
    else {
        msg_str = message_to_str(msg);
        if (!msg_str)
            return PEP_UNKNOWN_ERROR;
    }
    dump_out(filename, msg_str);
    free_message(enc_msg);
    free(msg_str);
    return PEP_STATUS_OK;
 }
 
// For when you ONLY care about the message
PEP_STATUS vanilla_read_file_and_decrypt(PEP_SESSION session, message** msg, const char* filename) {
    PEP_rating rating = PEP_rating_undefined;
    return vanilla_read_file_and_decrypt_with_rating(session, msg, filename, &rating);
}

PEP_STATUS vanilla_read_file_and_decrypt_with_rating(PEP_SESSION session, message** msg, const char* filename, PEP_rating* rating) {
    if (!session || !msg || !filename || !rating)
        return PEP_ILLEGAL_VALUE;
    PEP_STATUS status = PEP_STATUS_OK;

    message* enc_msg = slurp_message_file_into_struct(filename);
    if (!enc_msg)
        return PEP_UNKNOWN_ERROR;

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_decrypt_flags_t flags = 0;

    status = decrypt_message_2(session, enc_msg, &dec_msg, &keylist, &flags);
    if (dec_msg) {
        *msg = dec_msg;
        *rating = dec_msg->rating;
    }
    else
        *rating = enc_msg->rating;
    free_stringlist(keylist); // no one cares
    free_message(enc_msg);
    return status;
}

void wipe_message_ptr(message** msg_ptr) {
    if (msg_ptr) {
        free_message(*msg_ptr);
        *msg_ptr = NULL;
    }
}

int util_delete_filepath(const char *filepath,
                         const struct stat *file_stat,
                         int ftw_info,
                         struct FTW * ftw_struct) {
    int retval = 0;
    switch (ftw_info) {
        case FTW_DP:
            retval = rmdir(filepath);
            break;
        case FTW_F:
        case FTW_SLN:
            retval = unlink(filepath);
            break;
        default:
            retval = -1;
    }

    return retval;
}

PEP_STATUS config_valid_passphrase(PEP_SESSION session, const char* fpr, std::vector<std::string> passphrases) {
    // Check to see if it currently works
    PEP_STATUS status = probe_encrypt(session, fpr);
    if (status == PEP_STATUS_OK || passphrases.empty())
        return status;
        
    for (auto && pass : passphrases) {
        config_passphrase(session, pass.c_str());
        status = probe_encrypt(session, fpr);
        if (status == PEP_STATUS_OK)
            break;
    }
    return status;
}

PEP_STATUS set_default_fpr_for_test(PEP_SESSION session, pEp_identity* ident,  bool unconditional) {
    if (EMPTYSTR(ident->fpr))
        return PEP_ILLEGAL_VALUE;
    PEP_STATUS status = PEP_STATUS_OK;
    if (EMPTYSTR(ident->user_id)) {
        char* cache_fpr = ident->fpr;
        ident->fpr = NULL;
        status = update_identity(session, ident);
        ident->fpr = cache_fpr;
        if (status != PEP_STATUS_OK)
            return status;
        if (EMPTYSTR(ident->user_id)) 
            return PEP_UNKNOWN_ERROR;
    }
    if (!unconditional)
        status = validate_fpr(session, ident, true, true);
    if (status == PEP_STATUS_OK)
        status = set_identity(session, ident);            
    return status;
}

PEP_STATUS set_fpr_preserve_ident(PEP_SESSION session, const pEp_identity* ident, const char* fpr, bool valid_only) {
    if (!ident || EMPTYSTR(fpr))
        return PEP_ILLEGAL_VALUE;
    pEp_identity* clone = identity_dup(ident);
    PEP_STATUS status = update_identity(session, clone);
    if (status != PEP_STATUS_OK)
        return status;
    if (clone->fpr)
        free(clone->fpr);    
    clone->fpr = strdup(fpr);
    status = set_default_fpr_for_test(session, clone, !valid_only);
    free_identity(clone);
    return status;
}

PEP_STATUS TestUtilsPreset::import_preset_key(PEP_SESSION session,
                                              TestUtilsPreset::ident_preset preset_name,
                                              bool private_also) {
    string pubkey_dir = "test_keys/pub/";
    string privkey_dir = "test_keys/priv/";
    const char* key_prefix = TestUtilsPreset::presets[preset_name].key_prefix;
    string pubkey_file = pubkey_dir + key_prefix + "_pub.asc";
    string privkey_file = privkey_dir + key_prefix + "_priv.asc";
    if (!slurp_and_import_key(session, pubkey_file.c_str()))
        return PEP_KEY_NOT_FOUND;
    if (private_also) {
        if (!slurp_and_import_key(session, privkey_file.c_str()))
            return PEP_KEY_NOT_FOUND;
    }

    return PEP_STATUS_OK;
}

PEP_STATUS TestUtilsPreset::set_up_preset(PEP_SESSION session,
                                          ident_preset preset_name,
                                          bool set_ident,
                                          bool set_fpr,
                                          bool set_pep,
                                          bool trust,
                                          bool set_own,
                                          bool setup_private,
                                          pEp_identity** ident) {
    if (set_own && !set_ident)
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS status = PEP_STATUS_OK;

    if (ident)
        *ident = NULL;

    pEp_identity* retval = NULL;

    if ((int)preset_name >= sizeof(presets))
        return PEP_ILLEGAL_VALUE;

    const TestUtilsPreset::IdentityInfo& preset = presets[preset_name];

    status = TestUtilsPreset::import_preset_key(session, preset_name, setup_private);
    if (status != PEP_STATUS_OK)
        return status;

    retval = new_identity(preset.email, NULL, preset.user_id, preset.name);
    if (!retval)
        return PEP_OUT_OF_MEMORY;

    // honestly probably happens anyway
    if (set_ident && status == PEP_STATUS_OK) {
        retval->fpr = set_fpr ? strdup(preset.fpr) : NULL;
        status = set_identity(session, retval);
    }

    if (set_own) {
        retval->me = true;
        status = set_own_key(session, retval, preset.fpr);
    }

    if (set_pep && status == PEP_STATUS_OK)
        status = set_as_pEp_user(session, retval);

    if (trust && status == PEP_STATUS_OK) {
        if (!retval->me)
            status = update_identity(session, retval);
        if (retval->comm_type >= PEP_ct_strong_but_unconfirmed) {
            retval->comm_type = (PEP_comm_type)(retval->comm_type | PEP_ct_confirmed);
            status = set_trust(session, retval);
        }
    }

    if (ident)
        *ident = retval;
    else
        free_identity(retval);

    return status;
}
/*
static PEP_STATUS set_up_preset(PEP_SESSION session,
                     ident_preset preset_name,
                     bool set_identity,
                     bool set_fpr,
                     bool set_pep,
                     bool trust,
                     bool set_own,
                     bool setup_private,
                     pEp_identity** ident);
*/
pEp_identity* TestUtilsPreset::generateAndSetOpenPGPPartnerIdentity(PEP_SESSION session,
                                                                    ident_preset preset_name,
                                                                    bool set_fpr,
                                                                    bool trust) {
    pEp_identity* retval = NULL;
    PEP_STATUS status = set_up_preset(session, preset_name, true, set_fpr, false, trust, false, false, &retval);
    if (status != PEP_STATUS_OK) {
        free(retval);
        retval = NULL;
    }
    return retval;

}

pEp_identity* TestUtilsPreset::generateAndSetpEpPartnerIdentity(PEP_SESSION session,
                                                                    ident_preset preset_name,
                                                                    bool set_fpr,
                                                                    bool trust) {
    pEp_identity* retval = NULL;
    PEP_STATUS status = set_up_preset(session, preset_name, true, set_fpr, true, trust, false, false, &retval);
    if (status != PEP_STATUS_OK) {
        free(retval);
        retval = NULL;
    }
    return retval;
}

pEp_identity* TestUtilsPreset::generateAndSetPrivateIdentity(PEP_SESSION session,
                                                             ident_preset preset_name) {
    pEp_identity* retval = NULL;
    PEP_STATUS status = set_up_preset(session, preset_name, true, true, true, true, true, true, &retval);
    if (status != PEP_STATUS_OK) {
        free(retval);
        retval = NULL;
    }
    return retval;
}

pEp_identity* TestUtilsPreset::generateOnlyPrivateIdentity(PEP_SESSION session,
                                                           ident_preset preset_name) {
    pEp_identity* retval = NULL;
    PEP_STATUS status = set_up_preset(session, preset_name, false, false, false, false, false, true, &retval);
    if (status != PEP_STATUS_OK) {
        free(retval);
        retval = NULL;
    }
    return retval;
}
pEp_identity* TestUtilsPreset::generateOnlyPrivateIdentityGrabFPR(PEP_SESSION session,
                                                           ident_preset preset_name) {
    pEp_identity* retval = NULL;
    PEP_STATUS status = set_up_preset(session, preset_name, false, false, false, false, false, true, &retval);
    if (status != PEP_STATUS_OK) {
        free(retval);
        retval = NULL;
    }
    else {
        retval->fpr = strdup(TestUtilsPreset::presets[preset_name].fpr);
    }

    return retval;
}

pEp_identity* TestUtilsPreset::generateOnlyPartnerIdentity(PEP_SESSION session,
                                                           ident_preset preset_name) {
    pEp_identity* retval = NULL;
    PEP_STATUS status = set_up_preset(session, preset_name, false, false, false, false, false, false, &retval);
    if (status != PEP_STATUS_OK) {
        free(retval);
        retval = NULL;
    }
    return retval;
}

pEp_identity* TestUtilsPreset::generateOnlyPartnerIdentityGrabFPR(PEP_SESSION session,
                                                                  ident_preset preset_name) {
    pEp_identity* retval = NULL;
    PEP_STATUS status = set_up_preset(session, preset_name, false, false, false, false, false, true, &retval);
    if (status != PEP_STATUS_OK) {
        free(retval);
        retval = NULL;
    }
    else {
        retval->fpr = strdup(TestUtilsPreset::presets[preset_name].fpr);
    }
    return retval;
}

int NullBuffer::overflow(int c) {
    return c;
}



#ifndef DEBUG_OUTPUT
std::ostream output_stream(new NullBuffer());
#endif

void print_mail(message* msg) {
    char* outmsg = NULL;
    mime_encode_message(msg, false, &outmsg, false);
 //   output_stream << outmsg << endl;
    cout << outmsg << endl;
    free(outmsg);
}
