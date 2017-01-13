// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "platform.h"
#include "pEp_internal.h"
#include "pgp_gpg.h"

#include <limits.h>

#include "wrappers.h"

#define _GPGERR(X) ((X) & 0xffffL)

static void *gpgme;
static struct gpg_s gpg;

static bool ensure_config_values(stringlist_t *keys, stringlist_t *values, const char* config_file_path)
{
    static char buf[MAX_LINELENGTH];
    int r;
    FILE *f;
    stringlist_t *_k;
    stringlist_t *_v;
    unsigned int i;
    unsigned int found = 0;

    f = Fopen(config_file_path, "r");
    if (f == NULL && errno == ENOMEM)
        return false;

    if (f != NULL) {
        int length = stringlist_length(keys);
        unsigned int n = (1 << length) - 1;

        // make sure we 1) have the same number of keys and values
        // and 2) we don't have more key/value pairs than
        // the size of the bitfield used to hold the indices
        // of key/value pairs matching keys in the config file.
        assert(length <= sizeof(unsigned int) * CHAR_BIT);
        assert(length == stringlist_length(values));
        if (!(length == stringlist_length(values) &&
              length <= sizeof(unsigned int) * CHAR_BIT)) {
            r = Fclose(f);
            assert(r == 0);

            return false;
        }

        do {
            char * s;

            s = Fgets(buf, MAX_LINELENGTH, f);
            if (!feof(f)) {
                assert(s);
                if (s == NULL)
                    return false;

                if (s && !feof(f)) {
                    char * rest;
                    char * t = strtok_r(s, " ", &rest);
                    for (i = 1, _k = keys, _v = values; _k != NULL;
                            _k = _k->next, _v = _v->next, i <<= 1) {
                        if (t && strncmp(t, _k->value, strlen(_k->value)) == 0)
                            found |= i;

                        if (i == n) {
                            r = Fclose(f);
                            return true;
                        }
                    }
                }
            }
        } while (!feof(f));
        f = Freopen(config_file_path, "a", f);
    }
    else {
        f = Fopen(config_file_path, "w");
    }

    assert(f);
    if (f == NULL)
        return false;

    for (i = 1, _k = keys, _v = values; _k != NULL; _k = _k->next,
            _v = _v->next, i <<= 1) {
        if ((found & i) == 0) {
            r = Fprintf(f, "%s %s\n", _k->value, _v->value);
            assert(r >= 0);
        }
    }

    r = Fclose(f);
    assert(r == 0);

    return true;
}


PEP_STATUS pgp_init(PEP_SESSION session, bool in_first)
{
    PEP_STATUS status = PEP_STATUS_OK;
    gpgme_error_t gpgme_error;
    bool bResult;

    if (in_first) {
        stringlist_t *conf_keys   = new_stringlist("keyserver");
        stringlist_t *conf_values = new_stringlist("hkp://keys.gnupg.net");

        stringlist_add(conf_keys, "cert-digest-algo");
        stringlist_add(conf_values, "SHA256");

        stringlist_add(conf_keys, "no-emit-version");
        stringlist_add(conf_values, "");

        stringlist_add(conf_keys, "no-comments");
        stringlist_add(conf_values, "");

        stringlist_add(conf_keys, "personal-cipher-preferences");
        stringlist_add(conf_values, "AES AES256 AES192 CAST5");

        stringlist_add(conf_keys, "personal-digest-preferences");
        stringlist_add(conf_values, "SHA256 SHA512 SHA384 SHA224");

        bResult = ensure_config_values(conf_keys, conf_values, gpg_conf());

        free_stringlist(conf_keys);
        free_stringlist(conf_values);

        assert(bResult);
        if(!bResult){
            status = PEP_INIT_NO_GPG_HOME;
            goto pep_error;
        }

        conf_keys = new_stringlist("default-cache-ttl");
        conf_values = new_stringlist("300");

        stringlist_add(conf_keys, "max-cache-ttl");
        stringlist_add(conf_values, "1200");

        bResult = ensure_config_values(conf_keys, conf_values, gpg_agent_conf());

        free_stringlist(conf_keys);
        free_stringlist(conf_values);

        assert(bResult);
        if(!bResult){
            status = PEP_INIT_NO_GPG_HOME; /* FIXME: Wrong error here? */
            goto pep_error;
        }

        gpgme = dlopen(LIBGPGME, RTLD_LAZY);
        if (gpgme == NULL) {
            status = PEP_INIT_CANNOT_LOAD_GPGME;
            goto pep_error;
        }

        memset(&gpg, 0, sizeof(struct gpg_s));

        gpg.gpgme_set_locale
            = (gpgme_set_locale_t) (intptr_t) dlsym(gpgme,
            "gpgme_set_locale");
        assert(gpg.gpgme_set_locale);

        gpg.gpgme_check
            = (gpgme_check_version_t) (intptr_t) dlsym(gpgme,
            "gpgme_check_version");
        assert(gpg.gpgme_check);

        gpg.gpgme_new
            = (gpgme_new_t) (intptr_t) dlsym(gpgme, "gpgme_new");
        assert(gpg.gpgme_new);

        gpg.gpgme_release
            = (gpgme_release_t) (intptr_t) dlsym(gpgme, "gpgme_release");
        assert(gpg.gpgme_release);

        gpg.gpgme_get_engine_info
            = (gpgme_get_engine_info_t) (intptr_t) dlsym(gpgme,
            "gpgme_get_engine_info");
        assert(gpg.gpgme_get_engine_info);

        gpg.gpgme_set_protocol
            = (gpgme_set_protocol_t) (intptr_t) dlsym(gpgme,
            "gpgme_set_protocol");
        assert(gpg.gpgme_set_protocol);

        gpg.gpgme_set_armor
            = (gpgme_set_armor_t) (intptr_t) dlsym(gpgme,
            "gpgme_set_armor");
        assert(gpg.gpgme_set_armor);

        gpg.gpgme_data_new
            = (gpgme_data_new_t) (intptr_t) dlsym(gpgme,
            "gpgme_data_new");
        assert(gpg.gpgme_data_new);

        gpg.gpgme_data_new_from_mem
            = (gpgme_data_new_from_mem_t) (intptr_t) dlsym(gpgme,
            "gpgme_data_new_from_mem");
        assert(gpg.gpgme_data_new_from_mem);

        gpg.gpgme_data_new_from_cbs
            = (gpgme_data_new_from_cbs_t) (intptr_t) dlsym(gpgme,
            "gpgme_data_new_from_cbs");
        assert(gpg.gpgme_data_new_from_cbs);

        gpg.gpgme_data_release
            = (gpgme_data_release_t) (intptr_t) dlsym(gpgme,
            "gpgme_data_release");
        assert(gpg.gpgme_data_release);

        gpg.gpgme_data_identify
            = (gpgme_data_identify_t) (intptr_t) dlsym(gpgme,
            "gpgme_data_identify");
        assert(gpg.gpgme_data_identify);

        gpg.gpgme_data_seek
            = (gpgme_data_seek_t) (intptr_t) dlsym(gpgme,
            "gpgme_data_seek");
        assert(gpg.gpgme_data_seek);

        gpg.gpgme_data_read
            = (gpgme_data_read_t) (intptr_t) dlsym(gpgme,
            "gpgme_data_read");
        assert(gpg.gpgme_data_read);

        gpg.gpgme_op_decrypt
            = (gpgme_op_decrypt_t) (intptr_t) dlsym(gpgme,
            "gpgme_op_decrypt");
        assert(gpg.gpgme_op_decrypt);

        gpg.gpgme_op_verify
            = (gpgme_op_verify_t) (intptr_t) dlsym(gpgme,
            "gpgme_op_verify");
        assert(gpg.gpgme_op_verify);

        gpg.gpgme_op_decrypt_verify
            = (gpgme_op_decrypt_verify_t) (intptr_t) dlsym(gpgme,
            "gpgme_op_decrypt_verify");
        assert(gpg.gpgme_op_decrypt_verify);

        gpg.gpgme_op_decrypt_result
            = (gpgme_op_decrypt_result_t) (intptr_t) dlsym(gpgme,
            "gpgme_op_decrypt_result");
        assert(gpg.gpgme_op_decrypt_result);

        gpg.gpgme_op_encrypt_sign
            = (gpgme_op_encrypt_sign_t) (intptr_t) dlsym(gpgme,
            "gpgme_op_encrypt_sign");
        assert(gpg.gpgme_op_encrypt_sign);

        gpg.gpgme_op_verify_result
            = (gpgme_op_verify_result_t) (intptr_t) dlsym(gpgme,
            "gpgme_op_verify_result");
        assert(gpg.gpgme_op_verify_result);

        gpg.gpgme_signers_clear
            = (gpgme_signers_clear_t) (intptr_t) dlsym(gpgme,
            "gpgme_signers_clear");
        assert(gpg.gpgme_signers_clear);

        gpg.gpgme_signers_add
            = (gpgme_signers_add_t) (intptr_t) dlsym(gpgme,
            "gpgme_signers_add");
        assert(gpg.gpgme_signers_add);

        gpg.gpgme_get_key
            = (gpgme_get_key_t) (intptr_t) dlsym(gpgme, "gpgme_get_key");
        assert(gpg.gpgme_get_key);

        gpg.gpgme_op_genkey
            = (gpgme_op_genkey_t) (intptr_t) dlsym(gpgme,
            "gpgme_op_genkey");
        assert(gpg.gpgme_op_genkey);

        gpg.gpgme_op_genkey_result
            = (gpgme_op_genkey_result_t) (intptr_t) dlsym(gpgme,
            "gpgme_op_genkey_result");
        assert(gpg.gpgme_op_genkey_result);

        gpg.gpgme_op_delete = (gpgme_op_delete_t) (intptr_t)
            dlsym(gpgme, "gpgme_op_delete");
        assert(gpg.gpgme_op_delete);

        gpg.gpgme_op_import = (gpgme_op_import_t) (intptr_t)
            dlsym(gpgme, "gpgme_op_import");
        assert(gpg.gpgme_op_import);

        gpg.gpgme_op_import_result
            = (gpgme_op_import_result_t) (intptr_t) dlsym(gpgme,
            "gpgme_op_import_result");
        assert(gpg.gpgme_op_import_result);

        gpg.gpgme_op_export = (gpgme_op_export_t) (intptr_t)
            dlsym(gpgme, "gpgme_op_export");
        assert(gpg.gpgme_op_export);

        gpg.gpgme_set_keylist_mode = (gpgme_set_keylist_mode_t) (intptr_t)
            dlsym(gpgme, "gpgme_set_keylist_mode");
        assert(gpg.gpgme_set_keylist_mode);

        gpg.gpgme_get_keylist_mode = (gpgme_get_keylist_mode_t) (intptr_t)
            dlsym(gpgme, "gpgme_get_keylist_mode");
        assert(gpg.gpgme_get_keylist_mode);

        gpg.gpgme_op_keylist_start = (gpgme_op_keylist_start_t) (intptr_t)
            dlsym(gpgme, "gpgme_op_keylist_start");
        assert(gpg.gpgme_op_keylist_start);

        gpg.gpgme_op_keylist_next = (gpgme_op_keylist_next_t) (intptr_t)
            dlsym(gpgme, "gpgme_op_keylist_next");
        assert(gpg.gpgme_op_keylist_next);

        gpg.gpgme_op_keylist_end = (gpgme_op_keylist_end_t) (intptr_t)
            dlsym(gpgme, "gpgme_op_keylist_end");
        assert(gpg.gpgme_op_keylist_end);

        gpg.gpgme_op_import_keys = (gpgme_op_import_keys_t) (intptr_t)
            dlsym(gpgme, "gpgme_op_import_keys");
        assert(gpg.gpgme_op_import_keys);

        gpg.gpgme_key_ref = (gpgme_key_ref_t) (intptr_t)
            dlsym(gpgme, "gpgme_key_ref");
        assert(gpg.gpgme_key_ref);

        gpg.gpgme_key_unref = (gpgme_key_unref_t) (intptr_t)
            dlsym(gpgme, "gpgme_key_unref");
        assert(gpg.gpgme_key_unref);

		gpg.gpgme_key_release = (gpgme_key_release_t)(intptr_t)
			dlsym(gpgme, "gpgme_key_release");
		assert(gpg.gpgme_key_release);

        gpg.gpgme_op_edit = (gpgme_op_edit_t) (intptr_t)
            dlsym(gpgme, "gpgme_op_edit");
        assert(gpg.gpgme_op_edit);

        gpg.gpgme_io_write = (gpgme_io_write_t) (intptr_t)
            dlsym(gpgme, "gpgme_io_write");
        assert(gpg.gpgme_io_write);

        gpg.version = gpg.gpgme_check(NULL);

        const char * const cLocal = setlocale(LC_ALL, NULL);
        if (!cLocal || (strcmp(cLocal, "C") == 0))
            setlocale(LC_ALL, "");

        gpg.gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL));
#ifdef LC_MESSAGES // Windoze
        gpg.gpgme_set_locale (NULL, LC_MESSAGES, setlocale(LC_MESSAGES, NULL));
#endif
    }

    gpg.gpgme_check(NULL);
    gpgme_error = gpg.gpgme_new(&session->ctx);
    gpgme_error = _GPGERR(gpgme_error);
    if (gpgme_error != GPG_ERR_NO_ERROR) {
        status = PEP_INIT_GPGME_INIT_FAILED;
        goto pep_error;
    }
    assert(session->ctx);

    gpgme_error = gpg.gpgme_set_protocol(session->ctx, GPGME_PROTOCOL_OpenPGP);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error == GPG_ERR_NO_ERROR);

    gpg.gpgme_set_armor(session->ctx, 1);

    return PEP_STATUS_OK;

pep_error:
    pgp_release(session, in_first);
    return status;
}

void pgp_release(PEP_SESSION session, bool out_last)
{
    if (session->ctx) {
        gpg.gpgme_release(session->ctx);
        session->ctx = NULL;
    }

    if (out_last)
        if (gpgme)
            dlclose(gpgme);
}

PEP_STATUS pgp_decrypt_and_verify(
    PEP_SESSION session, const char *ctext, size_t csize,
    const char *dsigtext, size_t dsigsize,
    char **ptext, size_t *psize, stringlist_t **keylist
    )
{
    PEP_STATUS result;
    gpgme_error_t gpgme_error;
    gpgme_data_t cipher, plain;
    gpgme_data_type_t dt;

    stringlist_t *_keylist = NULL;
    //int i_key = 0;

    assert(session);
    assert(ctext);
    assert(csize);
    assert(ptext);
    assert(psize);
    assert(keylist);

    *ptext = NULL;
    *psize = 0;
    *keylist = NULL;

    gpgme_error = gpg.gpgme_data_new_from_mem(&cipher, ctext, csize, 0);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error == GPG_ERR_NO_ERROR);
    if (gpgme_error != GPG_ERR_NO_ERROR) {
        if (gpgme_error == GPG_ERR_ENOMEM)
            return PEP_OUT_OF_MEMORY;
        else
            return PEP_UNKNOWN_ERROR;
    }

    gpgme_error = gpg.gpgme_data_new(&plain);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error == GPG_ERR_NO_ERROR);
    if (gpgme_error != GPG_ERR_NO_ERROR) {
        gpg.gpgme_data_release(cipher);
        if (gpgme_error == GPG_ERR_ENOMEM)
            return PEP_OUT_OF_MEMORY;
        else
            return PEP_UNKNOWN_ERROR;
    }

    dt = gpg.gpgme_data_identify(cipher);
    switch (dt) {
#if GPGME_VERSION_NUMBER > 0x010600
    case GPGME_DATA_TYPE_PGP_ENCRYPTED:
#endif
    case GPGME_DATA_TYPE_PGP_SIGNED:
    case GPGME_DATA_TYPE_PGP_OTHER:
        if (dsigtext) {
            gpgme_error = gpg.gpgme_op_decrypt(session->ctx, cipher, plain);
        }
        else {
            gpgme_error = gpg.gpgme_op_decrypt_verify(session->ctx, cipher,
                plain);
        }
        gpgme_error = _GPGERR(gpgme_error);
        assert(gpgme_error != GPG_ERR_INV_VALUE);
        assert(gpgme_error != GPG_ERR_NO_DATA);

        switch (gpgme_error) {
            case GPG_ERR_NO_ERROR:
            {
                gpgme_verify_result_t gpgme_verify_result;
                char *_buffer = NULL;
                size_t reading;
                size_t length = gpg.gpgme_data_seek(plain, 0, SEEK_END);
                gpgme_signature_t gpgme_signature;

                assert(length != -1);
                gpg.gpgme_data_seek(plain, 0, SEEK_SET);

                // TODO: make things less memory consuming
                // the following algorithm allocates memory for the complete
                // text

                _buffer = malloc(length + 1);
                assert(_buffer);
                if (_buffer == NULL) {
                    gpg.gpgme_data_release(plain);
                    gpg.gpgme_data_release(cipher);
                    return PEP_OUT_OF_MEMORY;
                }

                reading = gpg.gpgme_data_read(plain, _buffer, length);
                assert(length == reading);

                if (dsigtext) {  // Is this safe to do?
                    gpgme_data_t sigdata;
                    gpg.gpgme_data_new_from_mem(&sigdata, dsigtext,
                                                dsigsize, 0);
                    gpg.gpgme_op_verify(session->ctx, sigdata, plain, NULL);
                    gpg.gpgme_data_release(sigdata);
                }

                gpgme_verify_result =
                    gpg.gpgme_op_verify_result(session->ctx);
                assert(gpgme_verify_result);
                gpgme_signature = gpgme_verify_result->signatures;

                if (!gpgme_signature) {
                    // try cleartext sig verification
                    gpg.gpgme_op_verify(session->ctx, plain, NULL, plain);
                    gpgme_verify_result =
                        gpg.gpgme_op_verify_result(session->ctx);
                    assert(gpgme_verify_result);
                    gpgme_signature = gpgme_verify_result->signatures;                    
                }

                if (gpgme_signature) {
                    stringlist_t *k;
                    _keylist = new_stringlist(NULL);
                    assert(_keylist);
                    if (_keylist == NULL) {
                        gpg.gpgme_data_release(plain);
                        gpg.gpgme_data_release(cipher);
                        free(_buffer);
                        return PEP_OUT_OF_MEMORY;
                    }
                    k = _keylist;

                    result = PEP_DECRYPTED_AND_VERIFIED;
                    gpg.gpgme_check(NULL);
                    do {
                        switch (_GPGERR(gpgme_signature->status)) {
                        case GPG_ERR_NO_ERROR:
                        {
                            // Some versions of gpg returns signer's
                            // signing subkey fingerprint instead of
                            // signer's primary key fingerprint.
                            // This is meant to get signer's primary
                            // key fingerprint, using subkey's.

                            gpgme_key_t key = NULL;

                            gpgme_error = gpg.gpgme_get_key(session->ctx,
                                gpgme_signature->fpr, &key, 0);
                            gpgme_error = _GPGERR(gpgme_error);
                            assert(gpgme_error != GPG_ERR_ENOMEM);
                            if (gpgme_error == GPG_ERR_ENOMEM) {
                                free_stringlist(_keylist);
                                gpg.gpgme_data_release(plain);
                                gpg.gpgme_data_release(cipher);
                                free(_buffer);
                                return PEP_OUT_OF_MEMORY;
                            }
                            // Primary key is given as the first subkey
                            if (gpgme_error == GPG_ERR_NO_ERROR &&
                                key && key->subkeys && key->subkeys->fpr
                                && key->subkeys->fpr[0])
                            {
                                k = stringlist_add(k, key->subkeys->fpr);

                                gpg.gpgme_key_unref(key);

                                if (k == NULL) {
                                    free_stringlist(_keylist);
                                    gpg.gpgme_data_release(plain);
                                    gpg.gpgme_data_release(cipher);
                                    free(_buffer);
                                    return PEP_OUT_OF_MEMORY;
                                }
                            }
                            else
                            {
                                result = PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH;
                                break;
                            }
                            break;
                        }
                        case GPG_ERR_CERT_REVOKED:
                        case GPG_ERR_BAD_SIGNATURE:
                            result = PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH;
                            break;
                        case GPG_ERR_SIG_EXPIRED:
                        case GPG_ERR_KEY_EXPIRED:
                        case GPG_ERR_NO_PUBKEY:
                            k = stringlist_add(k, gpgme_signature->fpr);
                            if (k == NULL) {
                                free_stringlist(_keylist);
                                gpg.gpgme_data_release(plain);
                                gpg.gpgme_data_release(cipher);
                                free(_buffer);
                                return PEP_OUT_OF_MEMORY;
                            }
                            if (result == PEP_DECRYPTED_AND_VERIFIED)
                                result = PEP_DECRYPTED;
                            break;
                        case GPG_ERR_GENERAL:
                            break;
                        default:
                            if (result == PEP_DECRYPTED_AND_VERIFIED)
                                result = PEP_DECRYPTED;
                            break;
                        }
                    } while ((gpgme_signature = gpgme_signature->next));
                }
                else {
                    result = PEP_DECRYPTED;
                }

                if (result == PEP_DECRYPTED_AND_VERIFIED
                    || result == PEP_DECRYPTED) {
                    *ptext = _buffer;
                    *psize = reading;
                    (*ptext)[*psize] = 0; // safeguard for naive users
                    *keylist = _keylist;
                }
                else {
                    free_stringlist(_keylist);
                    free(_buffer);
                }
                break;
            }
            case GPG_ERR_BAD_PASSPHRASE:
                result = PEP_DECRYPT_NO_KEY;
                break;
            case GPG_ERR_DECRYPT_FAILED:
            default:
            {
                gpgme_decrypt_result_t gpgme_decrypt_result = gpg.gpgme_op_decrypt_result(session->ctx);
                result = PEP_DECRYPT_NO_KEY;

                if (gpgme_decrypt_result != NULL) {
                    if (gpgme_decrypt_result->unsupported_algorithm)
                        *keylist = new_stringlist(gpgme_decrypt_result->unsupported_algorithm);
                    else
                        *keylist = new_stringlist("");
                    assert(*keylist);
                    if (*keylist == NULL) {
                        result = PEP_OUT_OF_MEMORY;
                        break;
                    }
                    stringlist_t *_keylist = *keylist;
                    for (gpgme_recipient_t r = gpgme_decrypt_result->recipients; r != NULL; r = r->next) {
                        _keylist = stringlist_add(_keylist, r->keyid);
                        assert(_keylist);
                        if (_keylist == NULL) {
                            free_stringlist(*keylist);
                            *keylist = NULL;
                            result = PEP_OUT_OF_MEMORY;
                            break;
                        }
                    }
                    if (result == PEP_OUT_OF_MEMORY)
                        break;
                }
            }
        }
        break;

    default:
        result = PEP_DECRYPT_WRONG_FORMAT;
    }

    gpg.gpgme_data_release(plain);
    gpg.gpgme_data_release(cipher);
    return result;
}

PEP_STATUS pgp_verify_text(
    PEP_SESSION session, const char *text, size_t size,
    const char *signature, size_t sig_size, stringlist_t **keylist
    )
{
    PEP_STATUS result;
    gpgme_error_t gpgme_error;
    gpgme_data_t d_text, d_sig;
    stringlist_t *_keylist;

    assert(session);
    assert(text);
    assert(size);
    assert(signature);
    assert(sig_size);
    assert(keylist);

    *keylist = NULL;

    gpgme_error = gpg.gpgme_data_new_from_mem(&d_text, text, size, 0);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error == GPG_ERR_NO_ERROR);
    if (gpgme_error != GPG_ERR_NO_ERROR) {
        if (gpgme_error == GPG_ERR_ENOMEM)
            return PEP_OUT_OF_MEMORY;
        else
            return PEP_UNKNOWN_ERROR;
    }

    gpgme_error = gpg.gpgme_data_new_from_mem(&d_sig, signature, sig_size, 0);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error == GPG_ERR_NO_ERROR);
    if (gpgme_error != GPG_ERR_NO_ERROR) {
        gpg.gpgme_data_release(d_text);
        if (gpgme_error == GPG_ERR_ENOMEM)
            return PEP_OUT_OF_MEMORY;
        else
            return PEP_UNKNOWN_ERROR;
    }

    gpgme_error = gpg.gpgme_op_verify(session->ctx, d_sig, d_text, NULL);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error != GPG_ERR_INV_VALUE);

    switch (gpgme_error) {
    case GPG_ERR_NO_ERROR:
    {
        gpgme_verify_result_t gpgme_verify_result;
        gpgme_signature_t gpgme_signature;

        gpgme_verify_result =
            gpg.gpgme_op_verify_result(session->ctx);
        assert(gpgme_verify_result);
        gpgme_signature = gpgme_verify_result->signatures;

        if (gpgme_signature) {
            stringlist_t *k;
            _keylist = new_stringlist(NULL);
            assert(_keylist);
            if (_keylist == NULL) {
                gpg.gpgme_data_release(d_text);
                gpg.gpgme_data_release(d_sig);
                return PEP_OUT_OF_MEMORY;
            }
            k = _keylist;

            result = PEP_VERIFIED;
            do {
                gpgme_key_t key;
                memset(&key,0,sizeof(key));

                // GPGME may give subkey's fpr instead of primary key's fpr.
                // Therefore we ask for the primary fingerprint instead
                // we assume that gpgme_get_key can find key by subkey's fpr
                gpgme_error = gpg.gpgme_get_key(session->ctx,
                    gpgme_signature->fpr, &key, 0);
                gpgme_error = _GPGERR(gpgme_error);
                assert(gpgme_error != GPG_ERR_ENOMEM);
                if (gpgme_error == GPG_ERR_ENOMEM) {
                    free_stringlist(_keylist);
                    gpg.gpgme_data_release(d_text);
                    gpg.gpgme_data_release(d_sig);
                    return PEP_OUT_OF_MEMORY;
                }
                // Primary key is given as the first subkey
                if (gpgme_error == GPG_ERR_NO_ERROR &&
                    key && key->subkeys && key->subkeys->fpr
                    && key->subkeys->fpr[0])
                {
                    k = stringlist_add(k, key->subkeys->fpr);

                    gpg.gpgme_key_unref(key);

                    if (k == NULL) {
                        free_stringlist(_keylist);
                        gpg.gpgme_data_release(d_text);
                        gpg.gpgme_data_release(d_sig);
                        return PEP_OUT_OF_MEMORY;
                    }
                }
                else {
                    result = PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH;
                    break;
                }

                if (gpgme_signature->summary & GPGME_SIGSUM_RED) {
                    if (gpgme_signature->summary & GPGME_SIGSUM_KEY_EXPIRED
                        || gpgme_signature->summary & GPGME_SIGSUM_SIG_EXPIRED) {
                        if (result == PEP_VERIFIED
                            || result == PEP_VERIFIED_AND_TRUSTED)
                            result = PEP_UNENCRYPTED;
                    }
                    else {
                        result = PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH;
                        break;
                    }
                }
                else {
                    if (gpgme_signature->summary & GPGME_SIGSUM_VALID) {
                        if (result == PEP_VERIFIED)
                            result = PEP_VERIFIED_AND_TRUSTED;
                    }
                    if (gpgme_signature->summary & GPGME_SIGSUM_GREEN) {
                        // good
                    }
                    else if (gpgme_signature->summary & GPGME_SIGSUM_KEY_MISSING) {
                        result = PEP_VERIFY_NO_KEY;
                    }
                    else if (gpgme_signature->summary & GPGME_SIGSUM_SYS_ERROR) {
                        if (result == PEP_VERIFIED
                            || result == PEP_VERIFIED_AND_TRUSTED)
                            result = PEP_UNENCRYPTED;
                    }
                    else {
                        // do nothing
                    }
                }
            } while ((gpgme_signature = gpgme_signature->next));
            *keylist = _keylist;
        }
        else {
            result = PEP_UNENCRYPTED;
        }
        break;
    }
        break;
    case GPG_ERR_NO_DATA:
        result = PEP_DECRYPT_WRONG_FORMAT;
        break;
    case GPG_ERR_INV_VALUE:
    default:
        result = PEP_UNKNOWN_ERROR;
        break;
    }

    gpg.gpgme_data_release(d_text);
    gpg.gpgme_data_release(d_sig);

    return result;
}

PEP_STATUS pgp_encrypt_and_sign(
    PEP_SESSION session, const stringlist_t *keylist, const char *ptext,
    size_t psize, char **ctext, size_t *csize
    )
{
    PEP_STATUS result;
    gpgme_error_t gpgme_error;
    gpgme_data_t plain, cipher;
    gpgme_key_t *rcpt;
    gpgme_encrypt_flags_t flags;
    const stringlist_t *_keylist;
    int i, j;

    assert(session);
    assert(keylist);
    assert(ptext);
    assert(psize);
    assert(ctext);
    assert(csize);

    *ctext = NULL;
    *csize = 0;

    gpgme_error = gpg.gpgme_data_new_from_mem(&plain, ptext, psize, 0);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error == GPG_ERR_NO_ERROR);
    if (gpgme_error != GPG_ERR_NO_ERROR) {
        if (gpgme_error == GPG_ERR_ENOMEM)
            return PEP_OUT_OF_MEMORY;
        else
            return PEP_UNKNOWN_ERROR;
    }

    gpgme_error = gpg.gpgme_data_new(&cipher);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error == GPG_ERR_NO_ERROR);
    if (gpgme_error != GPG_ERR_NO_ERROR) {
        gpg.gpgme_data_release(plain);
        if (gpgme_error == GPG_ERR_ENOMEM)
            return PEP_OUT_OF_MEMORY;
        else
            return PEP_UNKNOWN_ERROR;
    }

    rcpt = calloc(stringlist_length(keylist) + 1, sizeof(gpgme_key_t));
    assert(rcpt);
    if (rcpt == NULL) {
        gpg.gpgme_data_release(plain);
        gpg.gpgme_data_release(cipher);
        return PEP_OUT_OF_MEMORY;
    }

    gpg.gpgme_signers_clear(session->ctx);

    for (_keylist = keylist, i = 0; _keylist != NULL; _keylist = _keylist->next, i++) {
        assert(_keylist->value);
        gpgme_error = gpg.gpgme_get_key(session->ctx, _keylist->value,
            &rcpt[i], 0);
        gpgme_error = _GPGERR(gpgme_error);
        assert(gpgme_error != GPG_ERR_ENOMEM);

        switch (gpgme_error) {
        case GPG_ERR_ENOMEM:
            for (j = 0; j<i; j++)
                gpg.gpgme_key_unref(rcpt[j]);
            free(rcpt);
            gpg.gpgme_data_release(plain);
            gpg.gpgme_data_release(cipher);
            return PEP_OUT_OF_MEMORY;
        case GPG_ERR_NO_ERROR:
            if (i == 0) {
                gpgme_error_t _gpgme_error = gpg.gpgme_signers_add(session->ctx, rcpt[0]);
                _gpgme_error = _GPGERR(_gpgme_error);
                assert(_gpgme_error == GPG_ERR_NO_ERROR);
            }
            break;
        case GPG_ERR_EOF:
            for (j = 0; j<i; j++)
                gpg.gpgme_key_unref(rcpt[j]);
            free(rcpt);
            gpg.gpgme_data_release(plain);
            gpg.gpgme_data_release(cipher);
            return PEP_KEY_NOT_FOUND;
        case GPG_ERR_AMBIGUOUS_NAME:
            for (j = 0; j<i; j++)
                gpg.gpgme_key_unref(rcpt[j]);
            free(rcpt);
            gpg.gpgme_data_release(plain);
            gpg.gpgme_data_release(cipher);
            return PEP_KEY_HAS_AMBIG_NAME;
        default: // GPG_ERR_INV_VALUE if CTX or R_KEY is not a valid pointer or
            // FPR is not a fingerprint or key ID
            for (j = 0; j<i; j++)
                gpg.gpgme_key_unref(rcpt[j]);
            free(rcpt);
            gpg.gpgme_data_release(plain);
            gpg.gpgme_data_release(cipher);
            return PEP_GET_KEY_FAILED;
        }
    }

    // TODO: remove that and replace with proper key management
    flags = GPGME_ENCRYPT_ALWAYS_TRUST;

    gpgme_error = gpg.gpgme_op_encrypt_sign(session->ctx, rcpt, flags,
        plain, cipher);
    gpgme_error = _GPGERR(gpgme_error);
    switch (gpgme_error) {
    case GPG_ERR_NO_ERROR:
    {
        char *_buffer = NULL;
        size_t reading;
        size_t length = gpg.gpgme_data_seek(cipher, 0, SEEK_END);
        assert(length != -1);
        gpg.gpgme_data_seek(cipher, 0, SEEK_SET);

        // TODO: make things less memory consuming
        // the following algorithm allocates a buffer for the complete text

        _buffer = malloc(length + 1);
        assert(_buffer);
        if (_buffer == NULL) {
            for (j = 0; j<stringlist_length(keylist); j++)
                gpg.gpgme_key_unref(rcpt[j]);
            free(rcpt);
            gpg.gpgme_data_release(plain);
            gpg.gpgme_data_release(cipher);
            return PEP_OUT_OF_MEMORY;
        }

        reading = gpg.gpgme_data_read(cipher, _buffer, length);
        assert(length == reading);

        *ctext = _buffer;
        *csize = reading;
        (*ctext)[*csize] = 0; // safeguard for naive users
        result = PEP_STATUS_OK;
        break;
    }
    default:
        result = PEP_UNKNOWN_ERROR;
    }

    for (j = 0; j<stringlist_length(keylist); j++)
        gpg.gpgme_key_unref(rcpt[j]);
    free(rcpt);
    gpg.gpgme_data_release(plain);
    gpg.gpgme_data_release(cipher);
    return result;
}

PEP_STATUS pgp_generate_keypair(
    PEP_SESSION session, pEp_identity *identity
    )
{
    gpgme_error_t gpgme_error;
    char *parms;
    const char *template =
        "<GnupgKeyParms format=\"internal\">\n"
        "Key-Type: RSA\n"
        "Key-Length: 4096\n"
        "Subkey-Type: RSA\n"
        "Subkey-Length: 4096\n"
        "Name-Real: %s\n"
        "Name-Email: %s\n"
        /* "Passphrase: %s\n" */
        "Expire-Date: 1y\n"
        "</GnupgKeyParms>\n";
    int result;
    gpgme_genkey_result_t gpgme_genkey_result;

    assert(session);
    assert(identity);
    assert(identity->address);
    assert(identity->fpr == NULL || identity->fpr[0] == 0);
    assert(identity->username);

    parms = calloc(1, PARMS_MAX);
    assert(parms);
    if (parms == NULL)
        return PEP_OUT_OF_MEMORY;

    result = snprintf(parms, PARMS_MAX, template, identity->username,
        identity->address); // , session->passphrase);
    assert(result < PARMS_MAX);
    if (result >= PARMS_MAX) {
        free(parms);
        return PEP_BUFFER_TOO_SMALL;
    }

    gpgme_error = gpg.gpgme_op_genkey(session->ctx, parms, NULL, NULL);
    gpgme_error = _GPGERR(gpgme_error);
    free(parms);

    switch (gpgme_error) {
    case GPG_ERR_NO_ERROR:
        break;
    case GPG_ERR_INV_VALUE:
        return PEP_ILLEGAL_VALUE;
    case GPG_ERR_GENERAL:
        return PEP_CANNOT_CREATE_KEY;
    default:
        assert(0);
        return PEP_UNKNOWN_ERROR;
    }

    gpgme_genkey_result = gpg.gpgme_op_genkey_result(session->ctx);
    assert(gpgme_genkey_result);
    assert(gpgme_genkey_result->fpr);

    free(identity->fpr);
    identity->fpr = strdup(gpgme_genkey_result->fpr);
    if (identity->fpr == NULL)
        return PEP_OUT_OF_MEMORY;

    return PEP_STATUS_OK;
}

PEP_STATUS pgp_delete_keypair(PEP_SESSION session, const char *fpr)
{
    gpgme_error_t gpgme_error;
    gpgme_key_t key;

    assert(session);
    assert(fpr);

    gpgme_error = gpg.gpgme_get_key(session->ctx, fpr, &key, 0);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error != GPG_ERR_ENOMEM);
    switch (gpgme_error) {
    case GPG_ERR_NO_ERROR:
        break;
    case GPG_ERR_EOF:
        return PEP_KEY_NOT_FOUND;
    case GPG_ERR_INV_VALUE:
        return PEP_ILLEGAL_VALUE;
    case GPG_ERR_AMBIGUOUS_NAME:
        return PEP_KEY_HAS_AMBIG_NAME;
    case GPG_ERR_ENOMEM:
        return PEP_OUT_OF_MEMORY;
    default:
        assert(0);
        return PEP_UNKNOWN_ERROR;
    }

    gpgme_error = gpg.gpgme_op_delete(session->ctx, key, 1);
    gpgme_error = _GPGERR(gpgme_error);
    gpg.gpgme_key_unref(key);
    switch (gpgme_error) {
    case GPG_ERR_NO_ERROR:
        break;
    case GPG_ERR_INV_VALUE:
        assert(0);
        return PEP_UNKNOWN_ERROR;
    case GPG_ERR_NO_PUBKEY:
        assert(0);
        return PEP_KEY_NOT_FOUND;
    case GPG_ERR_AMBIGUOUS_NAME:
        assert(0);
        return PEP_KEY_HAS_AMBIG_NAME;
    default:
        assert(0);
        return PEP_UNKNOWN_ERROR;
    }

    return PEP_STATUS_OK;
}

PEP_STATUS pgp_import_keydata(PEP_SESSION session, const char *key_data,
                              size_t size, identity_list **private_idents)
{
    gpgme_error_t gpgme_error;
    gpgme_data_t dh;

    assert(session);
    assert(key_data);

    if(private_idents)
        *private_idents = NULL;

    gpgme_error = gpg.gpgme_data_new_from_mem(&dh, key_data, size, 0);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error != GPG_ERR_ENOMEM);
    switch (gpgme_error) {
    case GPG_ERR_NO_ERROR:
        break;
    case GPG_ERR_ENOMEM:
        return PEP_OUT_OF_MEMORY;
    case GPG_ERR_INV_VALUE:
        assert(0);
        return PEP_UNKNOWN_ERROR;
    default:
        assert(0);
        return PEP_UNKNOWN_ERROR;
    }

    gpgme_import_result_t gpgme_import_result;

    gpgme_error = gpg.gpgme_op_import(session->ctx, dh);
    gpgme_error = _GPGERR(gpgme_error);
    switch (gpgme_error) {
    case GPG_ERR_NO_ERROR:
        if(private_idents)
        {
            gpgme_import_result =
                gpg.gpgme_op_import_result(session->ctx);
            assert(gpgme_import_result);
            if (!gpgme_import_result) {
                gpg.gpgme_data_release(dh);
                return PEP_UNKNOWN_ERROR;
            }

            gpgme_import_status_t import;
            for (import = gpgme_import_result->imports;
                 import;
                 import = import->next)
             {
                if (import &&
                    import->result == GPG_ERR_NO_ERROR &&
                    import->status & GPGME_IMPORT_SECRET )
                {
                    gpgme_key_t key = NULL;

                    gpgme_error = gpg.gpgme_get_key(session->ctx,
                        import->fpr, &key, 0);
                    gpgme_error = _GPGERR(gpgme_error);
                    assert(gpgme_error != GPG_ERR_ENOMEM);
                    if (gpgme_error == GPG_ERR_ENOMEM) {
                        gpg.gpgme_data_release(dh);
                        return PEP_OUT_OF_MEMORY;
                    }

                    if (gpgme_error == GPG_ERR_NO_ERROR &&
                        key && key->uids &&
                        key->uids->email && key->uids->name)
                    {
                        pEp_identity *ident = new_identity(
                             key->uids->email, import->fpr, NULL, key->uids->name);

                        gpg.gpgme_key_unref(key);

                        if (ident == NULL) {
                            gpg.gpgme_data_release(dh);
                            return PEP_OUT_OF_MEMORY;
                        }

                        *private_idents = identity_list_add(*private_idents, ident);

                        if (*private_idents == NULL) {
                            gpg.gpgme_data_release(dh);
                            return PEP_OUT_OF_MEMORY;
                        }
                    }
                    else
                    {
                        gpg.gpgme_key_unref(key);
                        gpg.gpgme_data_release(dh);
                        return PEP_UNKNOWN_ERROR;
                    }
                }
            }
        }
        break;
    case GPG_ERR_INV_VALUE:
        assert(0);
        gpg.gpgme_data_release(dh);
        return PEP_UNKNOWN_ERROR;
    case GPG_ERR_NO_DATA:
        gpg.gpgme_data_release(dh);
        return PEP_ILLEGAL_VALUE;
    default:
        assert(0);
        gpg.gpgme_data_release(dh);
        return PEP_UNKNOWN_ERROR;
    }

    gpg.gpgme_data_release(dh);
    return PEP_STATUS_OK;
}

PEP_STATUS pgp_export_keydata(
        PEP_SESSION session, const char *fpr, char **key_data, size_t *size,
        bool secret
    )
{
    gpgme_error_t gpgme_error;
    gpgme_data_t dh;
    size_t _size;
    char *buffer;
    int reading;

    assert(session);
    assert(fpr);
    assert(key_data);
    assert(size);

    gpgme_error = gpg.gpgme_data_new(&dh);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error != GPG_ERR_ENOMEM);
    switch (gpgme_error) {
    case GPG_ERR_NO_ERROR:
        break;
    case GPG_ERR_ENOMEM:
        return PEP_OUT_OF_MEMORY;
    case GPG_ERR_INV_VALUE:
        assert(0);
        return PEP_UNKNOWN_ERROR;
    default:
        assert(0);
        return PEP_UNKNOWN_ERROR;
    }

    if (secret)
        gpgme_error = gpg.gpgme_op_export(session->ctx, fpr,
            GPGME_EXPORT_MODE_SECRET, dh);
    else
        gpgme_error = gpg.gpgme_op_export(session->ctx, fpr,
            GPGME_EXPORT_MODE_MINIMAL, dh);
    gpgme_error = _GPGERR(gpgme_error);
    switch (gpgme_error) {
    case GPG_ERR_NO_ERROR:
        break;
    case GPG_ERR_EOF:
        gpg.gpgme_data_release(dh);
        return PEP_KEY_NOT_FOUND;
    case GPG_ERR_INV_VALUE:
        assert(0);
        gpg.gpgme_data_release(dh);
        return PEP_UNKNOWN_ERROR;
    default:
        assert(0);
        gpg.gpgme_data_release(dh);
        return PEP_UNKNOWN_ERROR;
    };

    _size = gpg.gpgme_data_seek(dh, 0, SEEK_END);
    assert(_size != -1);
    gpg.gpgme_data_seek(dh, 0, SEEK_SET);

    buffer = malloc(_size + 1);
    assert(buffer);
    if (buffer == NULL) {
        gpg.gpgme_data_release(dh);
        return PEP_OUT_OF_MEMORY;
    }

    reading = gpg.gpgme_data_read(dh, buffer, _size);
    assert(_size == reading);

    // safeguard for the naive user
    buffer[_size] = 0;

    *key_data = buffer;
    *size = _size;

    gpg.gpgme_data_release(dh);
    return PEP_STATUS_OK;
}

PEP_STATUS pgp_list_keyinfo(PEP_SESSION session, const char* pattern,
                            stringpair_list_t** keyinfo_list)
{
    gpgme_error_t gpgme_error;
    assert(session);
    assert(keyinfo_list);

    if (!session || !keyinfo_list)
        return PEP_ILLEGAL_VALUE;

    *keyinfo_list = NULL;

    gpgme_error = gpg.gpgme_op_keylist_start(session->ctx, pattern, 0);
    gpgme_error = _GPGERR(gpgme_error);

    switch(gpgme_error) {
        case GPG_ERR_NO_ERROR:
            break;
        case GPG_ERR_INV_VALUE:
            assert(0);
            return PEP_UNKNOWN_ERROR;
        default:
            gpg.gpgme_op_keylist_end(session->ctx);
            return PEP_GET_KEY_FAILED;
    };

    gpgme_key_t key;
    stringpair_list_t* _keyinfo_list = new_stringpair_list(NULL);
    stringpair_list_t* list_curr = _keyinfo_list;
    stringpair_t* pair = NULL;

    do {
        gpgme_error = gpg.gpgme_op_keylist_next(session->ctx, &key);
        gpgme_error = _GPGERR(gpgme_error);

        switch(gpgme_error) {
            case GPG_ERR_EOF:
                break;
            case GPG_ERR_NO_ERROR:
                assert(key);
                assert(key->subkeys);
                if (!key || !key->subkeys)
                    return PEP_GET_KEY_FAILED;

                // first subkey is primary key
                char* fpr = key->subkeys->fpr;
                char* uid = key->uids->uid;

                assert(fpr);
                assert(uid);
                if (!fpr)
                    return PEP_GET_KEY_FAILED;

                if (key->subkeys->revoked)
                    continue;

                pair = new_stringpair(fpr, uid);

                assert(pair);

                if (pair) {
                    list_curr = stringpair_list_add(list_curr, pair);
                    pair = NULL;

                    assert(list_curr);
                    if (list_curr != NULL)
                        break;
                    else
                        free_stringpair(pair);
                }
                // else fallthrough (list_curr or pair wasn't allocateable)
            case GPG_ERR_ENOMEM:
                free_stringpair_list(_keyinfo_list);
                gpg.gpgme_op_keylist_end(session->ctx);
                return PEP_OUT_OF_MEMORY;
            default:
                gpg.gpgme_op_keylist_end(session->ctx);
                return PEP_UNKNOWN_ERROR;
        }
    } while (gpgme_error != GPG_ERR_EOF);

    if (_keyinfo_list->value == NULL) {
        free_stringpair_list(_keyinfo_list);
        _keyinfo_list = NULL;
    }

    *keyinfo_list = _keyinfo_list;

    return PEP_STATUS_OK;
}

static void _switch_mode(pEpSession *session, gpgme_keylist_mode_t remove_mode,
    gpgme_keylist_mode_t add_mode)
{
    gpgme_error_t gpgme_error;
    gpgme_keylist_mode_t mode;

    mode = gpg.gpgme_get_keylist_mode(session->ctx);

    mode &= ~remove_mode;
    mode |= add_mode;

    gpgme_error = gpg.gpgme_set_keylist_mode(session->ctx, mode);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error == GPG_ERR_NO_ERROR);
}

PEP_STATUS pgp_recv_key(PEP_SESSION session, const char *pattern)
{
    gpgme_error_t gpgme_error;
    gpgme_key_t key;

    assert(session);
    assert(pattern);

    _switch_mode(session, GPGME_KEYLIST_MODE_LOCAL, GPGME_KEYLIST_MODE_EXTERN);

    gpgme_error = gpg.gpgme_op_keylist_start(session->ctx, pattern, 0);
    gpgme_error = _GPGERR(gpgme_error);
    switch (gpgme_error) {
    case GPG_ERR_NO_ERROR:
        break;
    case GPG_ERR_INV_VALUE:
        assert(0);
        _switch_mode(session, GPGME_KEYLIST_MODE_EXTERN, GPGME_KEYLIST_MODE_LOCAL);
        return PEP_UNKNOWN_ERROR;
    default:
        _switch_mode(session, GPGME_KEYLIST_MODE_EXTERN, GPGME_KEYLIST_MODE_LOCAL);
        return PEP_GET_KEY_FAILED;
    };

    gpgme_ctx_t import_ctx;
    gpgme_error = gpg.gpgme_new(&import_ctx);
    assert(gpgme_error == GPG_ERR_NO_ERROR);

    do {
        gpgme_error = gpg.gpgme_op_keylist_next(session->ctx, &key);
        gpgme_error = _GPGERR(gpgme_error);
        assert(gpgme_error != GPG_ERR_INV_VALUE);
        switch (gpgme_error) {
        case GPG_ERR_EOF:
            break;
        case GPG_ERR_NO_ERROR:
        {
            gpgme_error_t gpgme_error;
            gpgme_key_t keys[2];

            keys[0] = key;
            keys[1] = NULL;

            gpgme_error = gpg.gpgme_op_import_keys(import_ctx, keys);
            gpgme_error = _GPGERR(gpgme_error);
            gpg.gpgme_key_unref(key);
            assert(gpgme_error != GPG_ERR_INV_VALUE);
            assert(gpgme_error != GPG_ERR_CONFLICT);
        }
            break;
        case GPG_ERR_ENOMEM:
            gpg.gpgme_op_keylist_end(session->ctx);
            gpg.gpgme_release(import_ctx);
            _switch_mode(session, GPGME_KEYLIST_MODE_EXTERN, GPGME_KEYLIST_MODE_LOCAL);
            return PEP_OUT_OF_MEMORY;
        default:
            gpg.gpgme_op_keylist_end(session->ctx);
            gpg.gpgme_release(import_ctx);
            _switch_mode(session, GPGME_KEYLIST_MODE_EXTERN, GPGME_KEYLIST_MODE_LOCAL);
            return PEP_UNKNOWN_ERROR;
        };
    } while (gpgme_error != GPG_ERR_EOF);

    gpg.gpgme_op_keylist_end(session->ctx);
    gpg.gpgme_release(import_ctx);
    _switch_mode(session, GPGME_KEYLIST_MODE_EXTERN, GPGME_KEYLIST_MODE_LOCAL);
    return PEP_STATUS_OK;
}


static PEP_STATUS _pgp_search_keys(PEP_SESSION session, const char* pattern,
                            stringlist_t** keylist,
                            int private_only) {
    gpgme_error_t gpgme_error;
    gpgme_key_t key;

    assert(session);
    assert(pattern);
    assert(keylist);

    *keylist = NULL;

    gpgme_error = gpg.gpgme_op_keylist_start(session->ctx, pattern, private_only);
    gpgme_error = _GPGERR(gpgme_error);
    switch (gpgme_error) {
        case GPG_ERR_NO_ERROR:
            break;
        case GPG_ERR_INV_VALUE:
            assert(0);
            return PEP_UNKNOWN_ERROR;
        default:
            gpg.gpgme_op_keylist_end(session->ctx);
            return PEP_GET_KEY_FAILED;
    };

    stringlist_t *_keylist = new_stringlist(NULL);
    stringlist_t *_k = _keylist;

    do {
        gpgme_error = gpg.gpgme_op_keylist_next(session->ctx, &key);
        gpgme_error = _GPGERR(gpgme_error);
        assert(gpgme_error != GPG_ERR_INV_VALUE);
        switch (gpgme_error) {
            case GPG_ERR_EOF:
                break;
            case GPG_ERR_NO_ERROR:
                assert(key);
                assert(key->subkeys);
                if(!key->subkeys)
                    break;
                assert(key->uids);
                gpgme_user_id_t kuid = key->uids;
                // check that at least one uid's email matches pattern exactly
                while(kuid) {
                    if(kuid->email && strcmp(kuid->email, pattern) == 0){
                        char *fpr = key->subkeys->fpr;
                        assert(fpr);
                        _k = stringlist_add(_k, fpr);
                        assert(_k);
                        if (_k == NULL){
                            free_stringlist(_keylist);
                            gpg.gpgme_op_keylist_end(session->ctx);
                            return PEP_OUT_OF_MEMORY;
                        }
                        break;
                    }
                    kuid = kuid->next;
                }
                break;
            case GPG_ERR_ENOMEM:
                free_stringlist(_keylist);
                gpg.gpgme_op_keylist_end(session->ctx);
                return PEP_OUT_OF_MEMORY;
            default:
                gpg.gpgme_op_keylist_end(session->ctx);
                return PEP_UNKNOWN_ERROR;
        };
    } while (gpgme_error != GPG_ERR_EOF);

    gpg.gpgme_op_keylist_end(session->ctx);
    if (_keylist->value == NULL) {
        free_stringlist(_keylist);
        _keylist = NULL;
    }
    *keylist = _keylist;
    return PEP_STATUS_OK;
}

PEP_STATUS pgp_find_keys(
    PEP_SESSION session, const char *pattern, stringlist_t **keylist
    )
{
    return _pgp_search_keys(session, pattern, keylist, 0);
}

PEP_STATUS pgp_find_private_keys(
    PEP_SESSION session, const char *pattern, stringlist_t **keylist
)
{
    return _pgp_search_keys(session, pattern, keylist, 1);
}

PEP_STATUS pgp_send_key(PEP_SESSION session, const char *pattern)
{
    gpgme_error_t gpgme_error;

    assert(session);
    assert(pattern);

    gpgme_error = gpg.gpgme_op_export(session->ctx, pattern,
        GPGME_EXPORT_MODE_EXTERN, NULL);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error != GPG_ERR_INV_VALUE);
    if (gpgme_error == GPG_ERR_NO_ERROR)
        return PEP_STATUS_OK;
    else
        return PEP_CANNOT_SEND_KEY;
}

PEP_STATUS pgp_get_key_rating(
    PEP_SESSION session,
    const char *fpr,
    PEP_comm_type *comm_type
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    gpgme_error_t gpgme_error;
    gpgme_key_t key;

    assert(session);
    assert(fpr);
    assert(comm_type);

    *comm_type = PEP_ct_unknown;

    gpgme_error = gpg.gpgme_op_keylist_start(session->ctx, fpr, 0);
    gpgme_error = _GPGERR(gpgme_error);
    switch (gpgme_error) {
    case GPG_ERR_NO_ERROR:
        break;
    case GPG_ERR_INV_VALUE:
        assert(0);
        return PEP_UNKNOWN_ERROR;
    default:
        return PEP_GET_KEY_FAILED;
    };

    gpgme_error = gpg.gpgme_op_keylist_next(session->ctx, &key);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error != GPG_ERR_INV_VALUE);

    if (key == NULL) {
        gpg.gpgme_op_keylist_end(session->ctx);
        return PEP_KEY_NOT_FOUND;
    }

    switch (key->protocol) {
    case GPGME_PROTOCOL_OpenPGP:
    case GPGME_PROTOCOL_DEFAULT:
        *comm_type = PEP_ct_OpenPGP_unconfirmed;
        break;
    case GPGME_PROTOCOL_CMS:
        *comm_type = PEP_ct_CMS_unconfirmed;
        break;
    default:
        *comm_type = PEP_ct_unknown;
        gpg.gpgme_op_keylist_end(session->ctx);
        return PEP_STATUS_OK;
    }

    switch (gpgme_error) {
    case GPG_ERR_EOF:
        break;
    case GPG_ERR_NO_ERROR:
        assert(key);
        assert(key->subkeys);
        for (gpgme_subkey_t sk = key->subkeys; sk != NULL; sk = sk->next) {
            if (sk->length < 1024)
                *comm_type = PEP_ct_key_too_short;
            else if (
                (
                (sk->pubkey_algo == GPGME_PK_RSA)
                || (sk->pubkey_algo == GPGME_PK_RSA_E)
                || (sk->pubkey_algo == GPGME_PK_RSA_S)
                )
                && sk->length == 1024
                )
                *comm_type = PEP_ct_OpenPGP_weak_unconfirmed;

            if (sk->invalid) {
                *comm_type = PEP_ct_key_b0rken;
                break;
            }
            if (sk->expired) {
                *comm_type = PEP_ct_key_expired;
                break;
            }
            if (sk->revoked) {
                *comm_type = PEP_ct_key_revoked;
                break;
            }
        }
        break;
    case GPG_ERR_ENOMEM:
        gpg.gpgme_op_keylist_end(session->ctx);
        *comm_type = PEP_ct_unknown;
        return PEP_OUT_OF_MEMORY;
    default:
        gpg.gpgme_op_keylist_end(session->ctx);
        return PEP_UNKNOWN_ERROR;
    };

    gpg.gpgme_op_keylist_end(session->ctx);

    return status;
}

static PEP_STATUS find_single_key(
        PEP_SESSION session,
        const char *fpr,
        gpgme_key_t *key
    )
{
    gpgme_error_t gpgme_error;

    *key = NULL;

    gpgme_error = gpg.gpgme_op_keylist_start(session->ctx, fpr, 0);
    gpgme_error = _GPGERR(gpgme_error);
    switch (gpgme_error) {
    case GPG_ERR_NO_ERROR:
        break;
    case GPG_ERR_INV_VALUE:
        assert(0);
        return PEP_UNKNOWN_ERROR;
    default:
        return PEP_GET_KEY_FAILED;
    };

    gpgme_error = gpg.gpgme_op_keylist_next(session->ctx, key);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error != GPG_ERR_INV_VALUE);

    gpg.gpgme_op_keylist_end(session->ctx);

    return PEP_STATUS_OK;
}

typedef struct _renew_state {
    enum {
        renew_command = 0,
        renew_date,
        renew_secret_key,
        renew_command2,
        renew_date2,
        renew_quit,
        renew_save,
        renew_exit,
        renew_error = -1
    } state;
    const char *date_ref;
} renew_state;

static gpgme_error_t renew_fsm(
        void *_handle,
        gpgme_status_code_t statuscode,
        const char *args,
        int fd
    )
{
    renew_state *handle = _handle;

    switch (handle->state) {
        case renew_command:
            if (statuscode == GPGME_STATUS_GET_LINE) {
                assert(strcmp(args, "keyedit.prompt") == 0);
                if (strcmp(args, "keyedit.prompt")) {
                    handle->state = renew_error;
                    return GPG_ERR_GENERAL;
                }
                gpg.gpgme_io_write(fd, "expire\n", 7);
                handle->state = renew_date;
            }
            break;

        case renew_date:
            if (statuscode == GPGME_STATUS_GET_LINE) {
                assert(strcmp(args, "keygen.valid") == 0);
                if (strcmp(args, "keygen.valid")) {
                    handle->state = renew_error;
                    return GPG_ERR_GENERAL;
                }
                gpg.gpgme_io_write(fd, handle->date_ref, 11);
                handle->state = renew_secret_key;
            }
            break;

        case renew_secret_key:
            if (statuscode == GPGME_STATUS_GET_LINE) {
                assert(strcmp(args, "keyedit.prompt") == 0);
                if (strcmp(args, "keyedit.prompt")) {
                    handle->state = renew_error;
                    return GPG_ERR_GENERAL;
                }
                gpg.gpgme_io_write(fd, "key 1\n", 6);
                handle->state = renew_command2;
            }
            break;

        case renew_command2:
            if (statuscode == GPGME_STATUS_GET_LINE) {
                assert(strcmp(args, "keyedit.prompt") == 0);
                if (strcmp(args, "keyedit.prompt")) {
                    handle->state = renew_error;
                    return GPG_ERR_GENERAL;
                }
                gpg.gpgme_io_write(fd, "expire\n", 7);
                handle->state = renew_date2;
            }
            break;

        case renew_date2:
            if (statuscode == GPGME_STATUS_GET_LINE) {
                assert(strcmp(args, "keygen.valid") == 0);
                if (strcmp(args, "keygen.valid")) {
                    handle->state = renew_error;
                    return GPG_ERR_GENERAL;
                }
                gpg.gpgme_io_write(fd, handle->date_ref, 11);
                handle->state = renew_quit;
            }
            break;

        case renew_quit:
            if (statuscode == GPGME_STATUS_GET_LINE) {
                assert(strcmp(args, "keyedit.prompt") == 0);
                if (strcmp(args, "keyedit.prompt")) {
                    handle->state = renew_error;
                    return GPG_ERR_GENERAL;
                }
                gpg.gpgme_io_write(fd, "quit\n", 5);
                handle->state = renew_save;
            }
            break;

        case renew_save:
            if (statuscode == GPGME_STATUS_GET_BOOL) {
                assert(strcmp(args, "keyedit.save.okay") == 0);
                if (strcmp(args, "keyedit.save.okay")) {
                    handle->state = renew_error;
                    return GPG_ERR_GENERAL;
                }
                gpg.gpgme_io_write(fd, "Y\n", 2);
                handle->state = renew_exit;
            }
            break;

        case renew_exit:
            break;

        case renew_error:
            return GPG_ERR_GENERAL;
    }

    return GPG_ERR_NO_ERROR;
}

static ssize_t _nullwriter(
        void *_handle,
        const void *buffer,
        size_t size
    )
{
    return size;
}

PEP_STATUS pgp_renew_key(
        PEP_SESSION session,
        const char *fpr,
        const timestamp *ts
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    gpgme_error_t gpgme_error;
    gpgme_key_t key;
    gpgme_data_t output;
    renew_state handle;
    char date_text[12];

    assert(session);
    assert(fpr);

    memset(&handle, 0, sizeof(renew_state));
    snprintf(date_text, 12, "%.4d-%.2d-%.2d\n", ts->tm_year + 1900,
            ts->tm_mon + 1, ts->tm_mday);
    handle.date_ref = date_text;

    status = find_single_key(session, fpr, &key);
    if (status != PEP_STATUS_OK)
        return status;

    struct gpgme_data_cbs data_cbs;
    memset(&data_cbs, 0, sizeof(struct gpgme_data_cbs));
    data_cbs.write = _nullwriter;
    gpg.gpgme_data_new_from_cbs(&output, &data_cbs, &handle);

    gpgme_error = gpg.gpgme_op_edit(session->ctx, key, renew_fsm, &handle,
            output);
    assert(gpgme_error == GPG_ERR_NO_ERROR);

    gpg.gpgme_data_release(output);
    gpg.gpgme_key_unref(key);

    return PEP_STATUS_OK;
}

typedef struct _revoke_state {
    enum {
        revoke_command = 0,
        revoke_approve,
        revoke_reason_code,
        revoke_reason_text,
        revoke_reason_ok,
        revoke_quit,
        revoke_save,
        revoke_exit,
        revoke_error = -1
    } state;
    const char *reason_ref;
} revoke_state;


/*** unused?
static bool isemptystring(const char *str)
{
    if (str == NULL)
        return true;

    for (; str; str++) {
        if (*str != ' ' && *str != '\t' && *str != '\n')
            return false;
    }

    return true;
}
***/


static gpgme_error_t revoke_fsm(
        void *_handle,
        gpgme_status_code_t statuscode,
        const char *args,
        int fd
    )
{
    revoke_state *handle = _handle;

    switch (handle->state) {
        case revoke_command:
            if (statuscode == GPGME_STATUS_GET_LINE) {
                assert(strcmp(args, "keyedit.prompt") == 0);
                if (strcmp(args, "keyedit.prompt")) {
                    handle->state = revoke_error;
                    return GPG_ERR_GENERAL;
                }
                gpg.gpgme_io_write(fd, "revkey\n", 7);
                handle->state = revoke_approve;
            }
            break;

        case revoke_approve:
            if (statuscode == GPGME_STATUS_GET_BOOL) {
                assert(strcmp(args, "keyedit.revoke.subkey.okay") == 0);
                if (strcmp(args, "keyedit.revoke.subkey.okay")) {
                    handle->state = revoke_error;
                    return GPG_ERR_GENERAL;
                }
                gpg.gpgme_io_write(fd, "Y\n", 2);
                handle->state = revoke_reason_code;
            }
            break;

        case revoke_reason_code:
            if (statuscode == GPGME_STATUS_GET_LINE) {
                assert(strcmp(args, "ask_revocation_reason.code") == 0);
                if (strcmp(args, "ask_revocation_reason.code")) {
                    handle->state = revoke_error;
                    return GPG_ERR_GENERAL;
                }
                gpg.gpgme_io_write(fd, "1\n", 2);
                handle->state = revoke_reason_text;
            }
            break;

        case revoke_reason_text:
            if (statuscode == GPGME_STATUS_GET_LINE) {
                assert(strcmp(args, "ask_revocation_reason.text") == 0);
                if (strcmp(args, "ask_revocation_reason.text")) {
                    handle->state = revoke_error;
                    return GPG_ERR_GENERAL;
                }
                // BUG: issues when reason given
                // Assertion failed: (gpg->cmd.code), function command_handler,
                // file engine-gpg.c, line 662.
                //
                // if (isemptystring(handle->reason_ref)) {
                    gpg.gpgme_io_write(fd, "\n", 1);
                // }
                // else {
                //     size_t len = strlen(handle->reason_ref);
                //     gpg.gpgme_io_write(fd, handle->reason_ref, len);
                //     if (handle->reason_ref[len - 1] == '\n')
                //         gpg.gpgme_io_write(fd, "\n", 1);
                //     else
                //         gpg.gpgme_io_write(fd, "\n\n", 2);
                // }
                handle->state = revoke_reason_ok;
            }
            break;

        case revoke_reason_ok:
            if (statuscode == GPGME_STATUS_GET_BOOL) {
                assert(strcmp(args, "ask_revocation_reason.okay") == 0);
                if (strcmp(args, "ask_revocation_reason.okay")) {
                    handle->state = revoke_error;
                    return GPG_ERR_GENERAL;
                }
                gpg.gpgme_io_write(fd, "Y\n", 2);
                handle->state = revoke_quit;
            }
            break;

        case revoke_quit:
            if (statuscode == GPGME_STATUS_GET_LINE) {
                assert(strcmp(args, "keyedit.prompt") == 0);
                if (strcmp(args, "keyedit.prompt")) {
                    handle->state = revoke_error;
                    return GPG_ERR_GENERAL;
                }
                gpg.gpgme_io_write(fd, "quit\n", 5);
                handle->state = revoke_save;
            }
            break;

        case revoke_save:
            if (statuscode == GPGME_STATUS_GET_BOOL) {
                assert(strcmp(args, "keyedit.save.okay") == 0);
                if (strcmp(args, "keyedit.save.okay")) {
                    handle->state = revoke_error;
                    return GPG_ERR_GENERAL;
                }
                gpg.gpgme_io_write(fd, "Y\n", 2);
                handle->state = revoke_exit;
            }
            break;

        case revoke_exit:
            break;

        case revoke_error:
            return GPG_ERR_GENERAL;
    }

    return GPG_ERR_NO_ERROR;
}

PEP_STATUS pgp_revoke_key(
        PEP_SESSION session,
        const char *fpr,
        const char *reason
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    gpgme_error_t gpgme_error;
    gpgme_key_t key;
    gpgme_data_t output;
    revoke_state handle;

    assert(session);
    assert(fpr);

    memset(&handle, 0, sizeof(revoke_state));
    handle.reason_ref = reason;

    status = find_single_key(session, fpr, &key);
    if (status != PEP_STATUS_OK)
        return status;

    struct gpgme_data_cbs data_cbs;
    memset(&data_cbs, 0, sizeof(struct gpgme_data_cbs));
    data_cbs.write = _nullwriter;
    gpg.gpgme_data_new_from_cbs(&output, &data_cbs, &handle);

    gpgme_error = gpg.gpgme_op_edit(session->ctx, key, revoke_fsm, &handle,
            output);
    assert(gpgme_error == GPG_ERR_NO_ERROR);

    gpg.gpgme_data_release(output);
    gpg.gpgme_key_unref(key);

    return PEP_STATUS_OK;
}

PEP_STATUS pgp_key_expired(
        PEP_SESSION session,
        const char *fpr,
        const time_t when,
        bool *expired
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    gpgme_key_t key;

    assert(session);
    assert(fpr);
    assert(expired);

    *expired = false;

    status = find_single_key(session, fpr, &key);
    if (status != PEP_STATUS_OK)
        return status;

    if ((key && key->expired) ||
        (key && key->subkeys && key->subkeys->expired))
    {
        // Already marked expired
        *expired = 1;
    }
    else if (key)
    {
        // Detect if will be expired
        // i.e. Check that keys capabilities will
        // not be expired at given time.
        gpgme_subkey_t _sk;
        bool crt_available = false;
        bool sgn_available = false;
        bool enc_available = false;
        for (_sk = key->subkeys; _sk; _sk = _sk->next) {
            if (_sk->expires > when || _sk->expires == 0) // not expired at that date ?
                                                          // Also, zero means "does not expire"
            {
                if (_sk->can_certify) crt_available = true;
                if (_sk->can_sign) sgn_available = true;
                if (_sk->can_encrypt) enc_available = true;
                // Authenticate is not used here.
            }
        }
        if(!(crt_available && sgn_available && enc_available))
        {
            *expired = 1;
        }
    }
    else
    {
        status = PEP_KEY_NOT_FOUND;
    }

    gpg.gpgme_key_unref(key);
    return status;
}

PEP_STATUS pgp_key_revoked(
        PEP_SESSION session,
        const char *fpr,
        bool *revoked
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    gpgme_key_t key;

    assert(session);
    assert(fpr);
    assert(revoked);

    *revoked = false;

    status = find_single_key(session, fpr, &key);
    if (status != PEP_STATUS_OK)
        return status;

    if (key && key->subkeys)
    {
        *revoked = key->subkeys->revoked;
    }
    else
    {
        status = PEP_KEY_NOT_FOUND;
    }

    gpg.gpgme_key_unref(key);
    return status;
}

PEP_STATUS pgp_key_created(
        PEP_SESSION session,
        const char *fpr,
        time_t *created
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    gpgme_key_t key;

    assert(session);
    assert(fpr);
    assert(created);

    *created = 0;

    status = find_single_key(session, fpr, &key);
    if (status != PEP_STATUS_OK)
        return status;

    if (key && key->subkeys)
    {
        *created = (time_t) key->subkeys->timestamp;
    }
    else
    {
        status = PEP_KEY_NOT_FOUND;
    }

    gpg.gpgme_key_unref(key);
    return status;
}

PEP_STATUS pgp_binary(const char **path)
{
    assert(path);
    if (path == NULL)
        return PEP_ILLEGAL_VALUE;

    *path = NULL;

    gpgme_engine_info_t info;
    int err = gpg.gpgme_get_engine_info(&info);
    assert(err == GPG_ERR_NO_ERROR);
    if (err != GPG_ERR_NO_ERROR)
        return PEP_OUT_OF_MEMORY;

    *path = info->file_name;

    return PEP_STATUS_OK;
}

PEP_STATUS pgp_contains_priv_key(PEP_SESSION session, const char *fpr,
        bool *has_private) {
    PEP_STATUS status = PEP_STATUS_OK;
    gpgme_key_t output_key;
    gpgme_error_t gpgerr = gpg.gpgme_get_key(session->ctx, fpr, &output_key, true);
    *has_private = false;
    switch (gpgerr) {
        case GPG_ERR_EOF:
        case GPG_ERR_INV_VALUE:
            status = PEP_KEY_NOT_FOUND;
            break;
        case GPG_ERR_AMBIGUOUS_NAME:
            status = PEP_KEY_HAS_AMBIG_NAME;
            break;
        case GPG_ERR_NO_ERROR:
            *has_private = true;
            gpg.gpgme_key_release(output_key);
            break;
        case GPG_ERR_ENOMEM:
            status = PEP_OUT_OF_MEMORY;
            break;
        default:
            status = PEP_UNKNOWN_ERROR;
            break;
    }
    return status;
}
