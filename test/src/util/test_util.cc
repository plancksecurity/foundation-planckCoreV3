#include "pEpEngine_test.h"
#include "pEpEngine.h"
#include "pEp_internal.h"
#include "message_api.h"
#include "test_util.h"
#include "TestConstants.h"

#include <fstream>
#include <sstream>
#include <stdexcept>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <ftw.h>

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
    else    
        status = update_identity(session, ident);

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
        case PEP_INIT_CANNOT_LOAD_GPGME:
            return "PEP_INIT_CANNOT_LOAD_GPGME";
        case PEP_INIT_GPGME_INIT_FAILED:
            return "PEP_INIT_GPGME_INIT_FAILED";
        case PEP_INIT_NO_GPG_HOME:
            return "PEP_INIT_NO_GPG_HOME";
        case PEP_INIT_NETPGP_INIT_FAILED:
            return "PEP_INIT_NETPGP_INIT_FAILED";
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
        case PEP_CANNOT_FIND_IDENTITY:
            return "PEP_CANNOT_FIND_IDENTITY";
        case PEP_CANNOT_SET_PERSON:
            return "PEP_CANNOT_SET_PERSON";
        case PEP_CANNOT_SET_PGP_KEYPAIR:
            return "PEP_CANNOT_SET_PGP_KEYPAIR";
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
        case PEP_rating_unencrypted_for_some:
            return "PEP_rating_unencrypted_for_some";
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
