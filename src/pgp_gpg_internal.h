// This file is under GNU General Public License 3.0
// see LICENSE.txt

#pragma once

#include <gpgme.h>

// init

typedef const char * (*gpgme_check_t)(const char*);
typedef gpgme_error_t (*gpgme_get_engine_info_t)(gpgme_engine_info_t *INFO);
typedef gpgme_error_t(*gpgme_set_locale_t)(gpgme_ctx_t CTX, int CATEGORY,
    const char *VALUE);
typedef gpgme_error_t(*gpgme_new_t)(gpgme_ctx_t *CTX);
typedef void(*gpgme_release_t)(gpgme_ctx_t CTX);
typedef gpgme_error_t(*gpgme_set_protocol_t)(gpgme_ctx_t CTX,
    gpgme_protocol_t PROTO);
typedef void(*gpgme_set_armor_t)(gpgme_ctx_t CTX, int YES);

// data

typedef gpgme_error_t(*gpgme_data_new_t)(gpgme_data_t *DH);
typedef gpgme_error_t(*gpgme_data_new_from_mem_t)(gpgme_data_t *DH,
    const char *BUFFER, size_t SIZE, int COPY);
typedef gpgme_error_t (*gpgme_data_new_from_cbs_t)(gpgme_data_t *DH,
        gpgme_data_cbs_t CBS, void *HANDLE);
typedef void(*gpgme_data_release_t)(gpgme_data_t DH);
typedef gpgme_data_type_t(*gpgme_data_identify_t)(gpgme_data_t DH);
typedef size_t(*gpgme_data_seek_t)(gpgme_data_t DH, size_t OFFSET,
    int WHENCE);
typedef size_t(*gpgme_data_read_t)(gpgme_data_t DH, void *BUFFER,
    size_t LENGTH);

// encrypt and decrypt

typedef gpgme_error_t(*gpgme_op_decrypt_t)(gpgme_ctx_t CTX,
    gpgme_data_t CIPHER, gpgme_data_t PLAIN);
typedef gpgme_error_t(*gpgme_op_verify_t)(gpgme_ctx_t CTX, gpgme_data_t SIG,
    gpgme_data_t SIGNED_TEXT, gpgme_data_t PLAIN);
typedef gpgme_error_t(*gpgme_op_decrypt_verify_t)(gpgme_ctx_t CTX,
    gpgme_data_t CIPHER, gpgme_data_t PLAIN);
typedef gpgme_decrypt_result_t(*gpgme_op_decrypt_result_t)(gpgme_ctx_t CTX);
typedef gpgme_error_t(*gpgme_op_encrypt_sign_t)(gpgme_ctx_t CTX,
    gpgme_key_t RECP[], gpgme_encrypt_flags_t FLAGS, gpgme_data_t PLAIN,
    gpgme_data_t CIPHER);
typedef gpgme_error_t(*gpgme_op_encrypt_t)(gpgme_ctx_t CTX,
        gpgme_key_t RECP[], gpgme_encrypt_flags_t FLAGS, gpgme_data_t PLAIN,
        gpgme_data_t CIPHER);
typedef gpgme_error_t(*gpgme_op_sign_t)(gpgme_ctx_t CTX,
        gpgme_data_t PLAIN, gpgme_data_t SIG, gpgme_sig_mode_t MODE);        
typedef gpgme_verify_result_t(*gpgme_op_verify_result_t)(gpgme_ctx_t CTX);
typedef void(*gpgme_signers_clear_t)(gpgme_ctx_t CTX);
typedef gpgme_error_t(*gpgme_signers_add_t)(gpgme_ctx_t CTX, const gpgme_key_t KEY);

// keys

typedef gpgme_error_t(*gpgme_get_key_t)(gpgme_ctx_t CTX, const char *FPR,
    gpgme_key_t *R_KEY, int SECRET);
typedef gpgme_error_t(*gpgme_op_genkey_t)(gpgme_ctx_t CTX, const char *PARMS,
    gpgme_data_t PUBLIC, gpgme_data_t SECRET);
typedef gpgme_genkey_result_t(*gpgme_op_genkey_result_t)(gpgme_ctx_t CTX);
typedef gpgme_error_t(*gpgme_op_delete_t)(gpgme_ctx_t CTX,
    const gpgme_key_t KEY, int ALLOW_SECRET);
typedef gpgme_error_t(*gpgme_op_import_t)(gpgme_ctx_t CTX,
    gpgme_data_t KEYDATA);
typedef gpgme_import_result_t(*gpgme_op_import_result_t)(gpgme_ctx_t CTX);
typedef gpgme_error_t(*gpgme_op_export_t)(gpgme_ctx_t CTX,
    const char *PATTERN, gpgme_export_mode_t MODE, gpgme_data_t KEYDATA);
typedef gpgme_error_t(*gpgme_set_keylist_mode_t)(gpgme_ctx_t CTX,
    gpgme_keylist_mode_t MODE);
typedef gpgme_keylist_mode_t(*gpgme_get_keylist_mode_t)(gpgme_ctx_t CTX);
typedef gpgme_error_t(*gpgme_op_keylist_start_t)(gpgme_ctx_t CTX,
    const char *PATTERN, int SECRET_ONLY);
typedef gpgme_error_t(*gpgme_op_keylist_next_t)(gpgme_ctx_t CTX,
    gpgme_key_t *R_KEY);
typedef gpgme_error_t(*gpgme_op_keylist_end_t)(gpgme_ctx_t CTX);
typedef gpgme_error_t(*gpgme_op_import_keys_t)(gpgme_ctx_t CTX,
    gpgme_key_t *KEYS);
typedef void(*gpgme_key_ref_t)(gpgme_key_t KEY);
typedef void(*gpgme_key_unref_t)(gpgme_key_t KEY);
typedef void(*gpgme_key_release_t)(gpgme_key_t KEY);
typedef gpgme_error_t (*gpgme_op_edit_t)(gpgme_ctx_t CTX, gpgme_key_t KEY,
        gpgme_edit_cb_t FNC, void *HANDLE, gpgme_data_t OUT);
typedef gpgme_ssize_t (*gpgme_io_write_t)(int fd, const void *buffer,
        size_t count);

#ifdef GPGME_VERSION_NUMBER 
#if (GPGME_VERSION_NUMBER >= 0x010700)
typedef gpgme_error_t(*gpgme_op_createkey_t)(gpgme_ctx_t CTX, 
    const char *USERID, const char *ALGO, unsigned long RESERVED, 
    unsigned long EXPIRES, gpgme_key_t EXTRAKEY, unsigned int FLAGS);
typedef gpgme_error_t(*gpgme_op_createsubkey_t)(gpgme_ctx_t ctx, 
    gpgme_key_t key, const char *algo, unsigned long reserved, 
    unsigned long expires, unsigned int flags);    
#endif
#endif


typedef gpgme_error_t(*gpgme_set_passphrase_cb_t)(gpgme_ctx_t ctx, 
		gpgme_passphrase_cb_t passfunc, void *hook_value);


struct gpg_s {
    const char * version;
    gpgme_check_t gpgme_check;
    gpgme_get_engine_info_t gpgme_get_engine_info;
    gpgme_set_locale_t gpgme_set_locale;
    gpgme_new_t gpgme_new;
    gpgme_release_t gpgme_release;
    gpgme_set_protocol_t gpgme_set_protocol;
    gpgme_set_armor_t gpgme_set_armor;

    gpgme_data_new_t gpgme_data_new;
    gpgme_data_new_from_mem_t gpgme_data_new_from_mem;
    gpgme_data_new_from_cbs_t gpgme_data_new_from_cbs;
    gpgme_data_release_t gpgme_data_release;
    gpgme_data_identify_t gpgme_data_identify;
    gpgme_data_seek_t gpgme_data_seek;
    gpgme_data_read_t gpgme_data_read;

    gpgme_op_decrypt_t gpgme_op_decrypt;
    gpgme_op_verify_t gpgme_op_verify;
    gpgme_op_decrypt_verify_t gpgme_op_decrypt_verify;
    gpgme_op_decrypt_result_t gpgme_op_decrypt_result;
    gpgme_op_encrypt_sign_t gpgme_op_encrypt_sign;
    gpgme_op_encrypt_t gpgme_op_encrypt;
    gpgme_op_sign_t gpgme_op_sign;    
    gpgme_op_verify_result_t gpgme_op_verify_result;
    gpgme_signers_clear_t gpgme_signers_clear;
    gpgme_signers_add_t gpgme_signers_add;

    gpgme_get_key_t gpgme_get_key;
    gpgme_op_genkey_t gpgme_op_genkey;
    gpgme_op_genkey_result_t gpgme_op_genkey_result;
#ifdef GPGME_VERSION_NUMBER 
#if (GPGME_VERSION_NUMBER >= 0x010700)    
    gpgme_op_createkey_t gpgme_op_createkey;
    gpgme_op_createsubkey_t gpgme_op_createsubkey;
#endif
#endif    
    gpgme_op_delete_t gpgme_op_delete;
    gpgme_op_import_t gpgme_op_import;
    gpgme_op_import_result_t gpgme_op_import_result;
    gpgme_op_export_t gpgme_op_export;
    gpgme_set_keylist_mode_t gpgme_set_keylist_mode;
    gpgme_get_keylist_mode_t gpgme_get_keylist_mode;
    gpgme_op_keylist_start_t gpgme_op_keylist_start;
    gpgme_op_keylist_next_t gpgme_op_keylist_next;
    gpgme_op_keylist_end_t gpgme_op_keylist_end;
    gpgme_op_import_keys_t gpgme_op_import_keys;
    gpgme_key_ref_t gpgme_key_ref;
    gpgme_key_unref_t gpgme_key_unref;
	gpgme_key_release_t gpgme_key_release;
    gpgme_op_edit_t gpgme_op_edit;
    gpgme_io_write_t gpgme_io_write;

    gpgme_set_passphrase_cb_t gpgme_set_passphrase_cb;
};
