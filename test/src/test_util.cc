#include "pEpEngine_test.h"
#include "pEpEngine_test.h"
#include "pEpEngine.h"
#include "pEp_internal.h"
#include "message_api.h"
#include "test_util.h"
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

using namespace std;

std::string _main_test_home_dir;

#define BUF_MAX_PATHLEN 4097

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
    else
        status = _update_identity(session, ident, true);

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

message* string_to_msg(string infile) {
    message *out_msg = NULL;
    mime_decode_message(infile.c_str(), infile.size(), &out_msg, NULL);
    return out_msg;
}

char* message_to_str(message* msg) {
    char* retval = NULL;
    mime_encode_message(msg, false, &retval, false);
    return retval;
}

PEP_STATUS vanilla_encrypt_and_write_to_file(PEP_SESSION session, message* msg, const char* filename) {
    if (!session || !msg || !filename)
        return PEP_ILLEGAL_VALUE;
    message* enc_msg = NULL;
    PEP_STATUS status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    if (status != PEP_STATUS_OK)
        return status;
    if (!enc_msg)
        return PEP_UNKNOWN_ERROR;
    char* msg_str = NULL;
    msg_str = message_to_str(enc_msg);
    if (!msg_str)
        return PEP_UNKNOWN_ERROR;
    dump_out(filename, msg_str);
    free_message(enc_msg);
    free(msg_str);
    return PEP_STATUS_OK;
}

// For when you ONLY care about the message
PEP_STATUS vanilla_read_file_and_decrypt(PEP_SESSION session, message** msg, const char* filename) {
    if (!session || !msg || !filename)
        return PEP_ILLEGAL_VALUE;
    PEP_STATUS status = PEP_STATUS_OK;
    std::string inbox = slurp(filename);
    if (inbox.empty())
        return PEP_UNKNOWN_ERROR;

    message* enc_msg = NULL;
    mime_decode_message(inbox.c_str(), inbox.size(), &enc_msg, NULL);

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_decrypt_flags_t flags = 0;
    PEP_rating rating;

    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    if (dec_msg)
        *msg = dec_msg;
    free_stringlist(keylist); // no one cares
    free_message(enc_msg);
    return status;
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

#ifndef ENIGMAIL_MAY_USE_THIS

static PEP_STATUS update_identity_recip_list(PEP_SESSION session,
                                      identity_list* list) {

    PEP_STATUS status = PEP_STATUS_OK;

    if (!session)
        return PEP_UNKNOWN_ERROR;

    identity_list* id_list_ptr = NULL;

    for (id_list_ptr = list; id_list_ptr; id_list_ptr = id_list_ptr->next) {
        pEp_identity* curr_identity = id_list_ptr->ident;
        if (curr_identity) {
            if (!is_me(session, curr_identity)) {
                char* name_bak = curr_identity->username;
                curr_identity->username = NULL;
                status = _update_identity(session, curr_identity, true);
                if (name_bak &&
                    (EMPTYSTR(curr_identity->username) || strcmp(name_bak, curr_identity->username) != 0)) {
                    free(curr_identity->username);
                    curr_identity->username = name_bak;
                }
            }
            else
                status = _myself(session, curr_identity, false, false, false, true);
        if (status == PEP_ILLEGAL_VALUE || status == PEP_OUT_OF_MEMORY)
            return status;
        }
    }

    return PEP_STATUS_OK;
}

PEP_STATUS MIME_decrypt_message(
    PEP_SESSION session,
    const char *mimetext,
    size_t size,
    char** mime_plaintext,
    stringlist_t **keylist,
    PEP_rating *rating,
    PEP_decrypt_flags_t *flags,
    char** modified_src
)
{
    assert(mimetext);
    assert(mime_plaintext);
    assert(keylist);
    assert(rating);
    assert(flags);
    assert(modified_src);

    if (!(mimetext && mime_plaintext && keylist && rating && flags && modified_src))
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS status = PEP_STATUS_OK;
    PEP_STATUS decrypt_status = PEP_CANNOT_DECRYPT_UNKNOWN;

    message* tmp_msg = NULL;
    message* dec_msg = NULL;
    *mime_plaintext = NULL;

    status = mime_decode_message(mimetext, size, &tmp_msg, NULL);
    if (status != PEP_STATUS_OK)
        goto pEp_error;

    tmp_msg->dir = PEP_dir_incoming;
    // MIME decode message delivers only addresses. We need more.
    if (tmp_msg->from) {
        if (!is_me(session, tmp_msg->from))
            status = _update_identity(session, (tmp_msg->from), true);
        else
            status = _myself(session, tmp_msg->from, false, true, false, true);

        if (status == PEP_ILLEGAL_VALUE || status == PEP_OUT_OF_MEMORY)
            goto pEp_error;
    }

    status = update_identity_recip_list(session, tmp_msg->to);
    if (status != PEP_STATUS_OK)
        goto pEp_error;

    status = update_identity_recip_list(session, tmp_msg->cc);
    if (status != PEP_STATUS_OK)
        goto pEp_error;

    status = update_identity_recip_list(session, tmp_msg->bcc);
    if (status != PEP_STATUS_OK)
        goto pEp_error;

    decrypt_status = decrypt_message(session,
                                     tmp_msg,
                                     &dec_msg,
                                     keylist,
                                     rating,
                                     flags);


    if (!dec_msg && (decrypt_status == PEP_UNENCRYPTED || decrypt_status == PEP_VERIFIED)) {
        dec_msg = message_dup(tmp_msg);
    }

    if (decrypt_status > PEP_CANNOT_DECRYPT_UNKNOWN || !dec_msg)
    {
        status = decrypt_status;
        goto pEp_error;
    }

    if (*flags & PEP_decrypt_flag_src_modified) {
        mime_encode_message(tmp_msg, false, modified_src, false);
        if (!modified_src) {
            *flags &= (~PEP_decrypt_flag_src_modified);
            decrypt_status = PEP_CANNOT_REENCRYPT; // Because we couldn't return it, I guess.
        }
    }

    // FIXME: test with att
    status = mime_encode_message(dec_msg, false, mime_plaintext, false);

    if (status == PEP_STATUS_OK)
    {
        free(tmp_msg);
        free(dec_msg);
        return decrypt_status;
    }

pEp_error:
    free_message(tmp_msg);
    free_message(dec_msg);

    return status;
}

PEP_STATUS MIME_encrypt_message(
    PEP_SESSION session,
    const char *mimetext,
    size_t size,
    stringlist_t* extra,
    char** mime_ciphertext,
    PEP_enc_format enc_format,
    PEP_encrypt_flags_t flags
)
{
    PEP_STATUS status = PEP_STATUS_OK;
    PEP_STATUS tmp_status = PEP_STATUS_OK;
    message* tmp_msg = NULL;
    message* enc_msg = NULL;
    message* ret_msg = NULL;                             

    status = mime_decode_message(mimetext, size, &tmp_msg, NULL);
    if (status != PEP_STATUS_OK)
        goto pEp_error;

    // MIME decode message delivers only addresses. We need more.
    if (tmp_msg->from) {
        char* own_id = NULL;
        status = get_default_own_userid(session, &own_id);
        free(tmp_msg->from->user_id);
    
        if (status != PEP_STATUS_OK || !own_id) {
            tmp_msg->from->user_id = strdup(PEP_OWN_USERID);
        }
        else {
            tmp_msg->from->user_id = own_id; // ownership transfer
        }
    
        status = myself(session, tmp_msg->from);
        if (status != PEP_STATUS_OK)
            goto pEp_error;
    }
    
    // Own identities can be retrieved here where they would otherwise
    // fail because we lack all other information. This is ok and even
    // desired. FIXME: IS it?
    status = update_identity_recip_list(session, tmp_msg->to);
    if (status != PEP_STATUS_OK)
        goto pEp_error;
    
    status = update_identity_recip_list(session, tmp_msg->cc);
    if (status != PEP_STATUS_OK)
        goto pEp_error;
    
    status = update_identity_recip_list(session, tmp_msg->bcc);
    if (status != PEP_STATUS_OK)
        goto pEp_error;
    
    // This isn't incoming, though... so we need to reverse the direction
    tmp_msg->dir = PEP_dir_outgoing;
    status = encrypt_message(session,
                             tmp_msg,
                             extra,
                             &enc_msg,
                             enc_format,
                             flags);
    
    if (status == PEP_STATUS_OK || status == PEP_UNENCRYPTED)
        ret_msg = (status == PEP_STATUS_OK ? enc_msg : tmp_msg);
    else                                
        goto pEp_error;

    if (status == PEP_STATUS_OK && !enc_msg) {
        status = PEP_UNKNOWN_ERROR;
        goto pEp_error;
    }
    
    tmp_status = mime_encode_message(ret_msg, false, mime_ciphertext, false);     
    if (tmp_status != PEP_STATUS_OK)
        status = tmp_status;

pEp_error:
    free_message(tmp_msg);
    free_message(enc_msg);

    return status;

}

PEP_STATUS MIME_encrypt_message_for_self(
    PEP_SESSION session,
    pEp_identity* target_id,
    const char *mimetext,
    size_t size,
    stringlist_t* extra,
    char** mime_ciphertext,
    PEP_enc_format enc_format,
    PEP_encrypt_flags_t flags
)
{
    PEP_STATUS status = PEP_STATUS_OK;
    message* tmp_msg = NULL;
    message* enc_msg = NULL;

    status = mime_decode_message(mimetext, size, &tmp_msg, NULL);
    if (status != PEP_STATUS_OK)
        goto pEp_error;

    // This isn't incoming, though... so we need to reverse the direction
    tmp_msg->dir = PEP_dir_outgoing;
    status = encrypt_message_for_self(session,
                                      target_id,
                                      tmp_msg,
                                      extra,
                                      &enc_msg,
                                      enc_format,
                                      flags);
    if (status != PEP_STATUS_OK)
        goto pEp_error;

    if (!enc_msg) {
        status = PEP_UNKNOWN_ERROR;
        goto pEp_error;
    }

    status = mime_encode_message(enc_msg, false, mime_ciphertext, false);

pEp_error:
    free_message(tmp_msg);
    free_message(enc_msg);

    return status;
}

#endif

PEP_STATUS set_up_preset(PEP_SESSION session,
                         pEp_test_ident_preset preset_name,
                         bool set_ident,
                         bool set_pep,
                         bool trust,
                         bool set_own,
                         bool setup_private,
                         pEp_identity** ident) {
    if (set_own && !set_ident)
        return PEP_ILLEGAL_VALUE;

    const char* name = NULL;
    const char* user_id = NULL;
    const char* email = NULL;
    const char* key_prefix = NULL;
    string pubkey_dir = "test_keys/pub/";
    string privkey_dir = "test_keys/priv/";
    const char* fpr = NULL;
    PEP_STATUS status = PEP_STATUS_OK;

    if (ident)
        *ident = NULL;

    pEp_identity* retval = NULL;

    switch (preset_name) {
        case ALICE:
            name = "Alice Spivak Hyatt";
            user_id = "ALICE";
            email = "pep.test.alice@pep-project.org";
            key_prefix = "pep-test-alice-0x6FF00E97";
            fpr = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";
            break;
        case APPLE:
            name = "Apple of my Computer";
            user_id = "APPLE";
            email = "pep.test.apple@pep-project.org";
            key_prefix = "pep-test-apple-0x1CCBC7D7";
            fpr = "3D8D9423D03DDF61B60161150313D94A1CCBC7D7";
            break;
        case BOB:
            name = "Bob Dog";
            user_id = "BOB";
            email = "pep.test.bob@pep-project.org";
            key_prefix = "pep-test-bob-0xC9C2EE39";
            fpr = "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39";
            break;
        case CAROL:
            name = "Carol Burnett";
            user_id = "CAROL";
            email = "pep-test-carol@pep-project.org";
            key_prefix = "pep-test-carol-0x42A85A42";
            fpr = "8DD4F5827B45839E9ACCA94687BDDFFB42A85A42";
            break;
        case DAVE:
            name = "The Hoff";
            user_id = "DAVE";
            email = "pep-test-dave@pep-project.org";
            key_prefix = "pep-test-dave-0xBB5BCCF6";
            fpr = "E8AC9779A2D13A15D8D55C84B049F489BB5BCCF6";
            break;
        case ERIN:
            name = "Erin Ireland";
            user_id = "ERIN";
            email = "pep-test-erin@pep-project.org";
            key_prefix = "pep-test-erin-0x9F8D7CBA";
            fpr = "1B0E197E8AE66277B8A024B9AEA69F509F8D7CBA";
            break;
        case FRANK:
            name = "Frank N. Furter";
            user_id = "FRANK";
            email = "pep-test-frank@pep-project.org";
            key_prefix = "pep-test-frank-0x9A7FC670";
            fpr = "B022B74476D8A8E1F01E55FBAB6972569A7FC670"; // currently expired
            break;
        case GABRIELLE:
            name = "Gabrielle Gonzales";
            user_id = "GABI";
            email = "pep-test-gabrielle@pep-project.org";
            key_prefix = "pep-test-gabrielle-0xE203586C";
            fpr = "906C9B8349954E82C5623C3C8C541BD4E203586C";
            break;
        case JOHN:
            name = "John Denver";
            user_id = "JOHN";
            email = "pep.test.john@pep-project.org";
            key_prefix = "pep-test-john-0x70DCF575";
            fpr = "AA2E4BEB93E5FE33DEFD8BE1135CD6D170DCF575";
            break;
        case ALEX:
            name = "Alex Braithwaite";
            user_id = "ALEX";
            email = "pep.test.alexander@peptest.ch";
            key_prefix = "pep.test.alexander-0x26B54E4E";
            fpr = "3AD9F60FAEB22675DB873A1362D6981326B54E4E";
            break;
        case ALEX_0:
            name = "Alex Braithwaite";
            user_id = "ALEX";
            email = "pep.test.alexander0@darthmama.org";
            key_prefix = "pep.test.alexander0-0x3B7302DB";
            fpr = "F4598A17D4690EB3B5B0F6A344F04E963B7302DB";
            break;
        case ALEX_1:
            name = "Alex Braithwaite";
            user_id = "ALEX";
            email = "pep.test.alexander1@darthmama.org";
            key_prefix = "pep.test.alexander1-0x541260F6";
            fpr = "59AF4C51492283522F6904531C09730A541260F6";
            break;
        case ALEX_2:
            name = "Alex Braithwaite";
            user_id = "ALEX";
            email = "pep.test.alexander2@darthmama.org";
            key_prefix = "pep.test.alexander2-0xA6512F30";
            fpr = "46A994F19077C05610870273C4B8AB0BA6512F30";
            break;
        case ALEX_3:
            name = "Alex Braithwaite";
            user_id = "ALEX";
            email = "pep.test.alexander3@darthmama.org";
            key_prefix = "pep.test.alexander3-0x724B3975";
            fpr = "5F7076BBD92E14EA49F0DF7C2CE49419724B3975";
            break;
        case ALEX_4:
            name = "Alex Braithwaite";
            user_id = "ALEX";
            email = "pep.test.alexander4@darthmama.org";
            key_prefix = "pep.test.alexander4-0x844B9DCF";
            fpr = "E95FFF95B8E2FDD4A12C3374395F1485844B9DCF";
            break;
        case ALEX_5:
            name = "Alex Braithwaite";
            user_id = "ALEX";
            email = "pep.test.alexander5@darthmama.org";
            key_prefix = "pep.test.alexander5-0x0773CD29";
            fpr = "58BCC2BF2AE1E3C4FBEAB89AD7838ACA0773CD29";
            break;
        case ALEX_6A:
            name = "Alex Braithwaite";
            user_id = "ALEX";
            email = "pep.test.alexander6@darthmama.org";
            key_prefix = "pep.test.alexander6-0x0019697D";
            fpr = "74D79B4496E289BD8A71B70BA8E2C4530019697D";
            break;
        case ALEX_6B:
            name = "Alex Braithwaite";
            user_id = "ALEX";
            email = "pep.test.alexander6@darthmama.org";
            key_prefix = "pep.test.alexander6-0x503B14D8";
            fpr = "2E21325D202A44BFD9C607FCF095B202503B14D8";
            break;
        case ALEX_6C:
            name = "Alex Braithwaite";
            user_id = "ALEX";
            email = "pep.test.alexander6@darthmama.org";
            key_prefix = "pep.test.alexander6-0xA216E95A";
            fpr = "3C1E713D8519D7F907E3142D179EAA24A216E95A";
            break;
        case ALEX_6D:
            name = "Alex Braithwaite";
            user_id = "ALEX";
            email = "pep.test.alexander6@darthmama.org";
            key_prefix = "pep.test.alexander6-0xBDA17020";
            fpr = "B4CE2F6947B6947C500F0687AEFDE530BDA17020";
            break;
        case BELLA:
            name = "Bella Cat";
            user_id = "BELLA";
            email = "pep.test.bella@peptest.ch";
            key_prefix = "pep.test.bella-0xAF516AAE";
            fpr = "5631BF1357326A02AA470EEEB815EF7FA4516AAE";
            break;
        case FENRIS:
            name = "Fenris Leto Hawke";
            user_id = "FENRIS";
            email = "pep.test.fenris@thisstilldoesntwork.lu";
            key_prefix = "pep.test.fenris-0x4F3D2900";
            fpr = "0969FA229DF21C832A64A04711B1B9804F3D2900";
            break;
        case SERCULLEN:
            name = "Cullen Rutherford";
            user_id = "CULLEN";
            email = "sercullen-test@darthmama.org";
            key_prefix = "sercullen-0x3CEAADED4"; // NB expired on purpose
            fpr = "1C9666D8B3E28F4AA3847DA89A6E75E3CEAADED4";
            break;
        case INQUISITOR:
            name = "Inquisitor Claire Trevelyan";
            user_id = "INQUISITOR";
            email = "inquisitor@darthmama.org";
            key_prefix = "inquisitor-0xA4728718_renewed";
            fpr = "8E8D2381AE066ABE1FEE509821BA977CA4728718";
            break;
        case BERND:
            name = "Bernd das Brot";
            user_id = "BERNDI";
            email = "bernd.das.brot@darthmama.org";
            key_prefix = "bernd.das.brot-0xCAFAA422";
            fpr = "F8CE0F7E24EB190A2FCBFD38D4B088A7CAFAA422";
            break;
        default:
            return PEP_CANNOT_SET_IDENTITY;
    }

    string pubkey_file = pubkey_dir + key_prefix + "_pub.asc";
    string privkey_file = privkey_dir + key_prefix + "_priv.asc";

    if (!slurp_and_import_key(session, pubkey_file.c_str()))
        return PEP_KEY_NOT_FOUND;

    if (setup_private) {
        if (!slurp_and_import_key(session, privkey_file.c_str()))
            return PEP_KEY_NOT_FOUND;
    }

    retval = new_identity(email, NULL, user_id, name);
    if (!retval)
        return PEP_OUT_OF_MEMORY;

    // honestly probably happens anyway
    if (set_ident && status == PEP_STATUS_OK)
        status = set_identity(session, retval);

    if (set_own) {
        retval->me = true;
        status = set_own_key(session, retval, fpr);
    }

    if (set_pep && status == PEP_STATUS_OK)
        status = set_as_pEp_user(session, retval);

    if (trust && status == PEP_STATUS_OK) {
        if (!retval->me)
            status = _update_identity(session, retval, true);
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

int NullBuffer::overflow(int c) {
    return c;
}

#ifndef DEBUG_OUTPUT
std::ostream output_stream(new NullBuffer());
#endif
