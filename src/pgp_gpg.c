#include "pgp_gpg.h"
#include "pEp_internal.h"

#define _GPGERR(X) ((X) & 0xffffL)

static bool ensure_keyserver()
{
    static char buf[MAX_LINELENGTH];
    int n;
    FILE *f = fopen(gpg_conf(), "r");

    if (f != NULL) {
        while (!feof(f)) {
            char * s = fgets(buf, MAX_LINELENGTH, f);
            if (s && !feof(f)) {
                char * t = strtok(s, " ");
                if (t && strcmp(t, "keyserver") == 0) {
                    fclose(f);
                    return true;
                }
            }
        }
        f = freopen(gpg_conf(), "a", f);
    }
    else {
        f = fopen(gpg_conf(), "w");
    }

    assert(f);
    if (f == NULL)
        return false;

    n = fprintf(f, "keyserver %s\n", DEFAULT_KEYSERVER);
    assert(n >= 0);
    fclose(f);

    return true;
}

PEP_STATUS pgp_init(PEP_SESSION session)
{
    pEpSession *_session = (pEpSession *) session;
    gpgme_error_t gpgme_error;
    bool bResult = ensure_keyserver();
    assert(bResult);

    _session->gpgme = dlopen(LIBGPGME, RTLD_LAZY);
    if (_session->gpgme == NULL) {
        free(_session);
        return PEP_INIT_CANNOT_LOAD_GPGME;
    }

    memset(&(_session->gpg), 0, sizeof(struct gpg_s));

    _session->gpg.gpgme_set_locale
        = (gpgme_set_locale_t) (intptr_t) dlsym(_session->gpgme,
        "gpgme_set_locale");
    assert(_session->gpg.gpgme_set_locale);

    _session->gpg.gpgme_check
        = (gpgme_check_version_t) (intptr_t) dlsym(_session->gpgme,
        "gpgme_check_version");
    assert(_session->gpg.gpgme_check);

    _session->gpg.gpgme_new
        = (gpgme_new_t) (intptr_t) dlsym(_session->gpgme, "gpgme_new");
    assert(_session->gpg.gpgme_new);

    _session->gpg.gpgme_release
        = (gpgme_release_t) (intptr_t) dlsym(_session->gpgme, "gpgme_release");
    assert(_session->gpg.gpgme_release);

    _session->gpg.gpgme_set_protocol
        = (gpgme_set_protocol_t) (intptr_t) dlsym(_session->gpgme,
        "gpgme_set_protocol");
    assert(_session->gpg.gpgme_set_protocol);

    _session->gpg.gpgme_set_armor
        = (gpgme_set_armor_t) (intptr_t) dlsym(_session->gpgme,
        "gpgme_set_armor");
    assert(_session->gpg.gpgme_set_armor);

    _session->gpg.gpgme_data_new
        = (gpgme_data_new_t) (intptr_t) dlsym(_session->gpgme,
        "gpgme_data_new");
    assert(_session->gpg.gpgme_data_new);

    _session->gpg.gpgme_data_new_from_mem
        = (gpgme_data_new_from_mem_t) (intptr_t) dlsym(_session->gpgme,
        "gpgme_data_new_from_mem");
    assert(_session->gpg.gpgme_data_new_from_mem);

    _session->gpg.gpgme_data_release
        = (gpgme_data_release_t) (intptr_t) dlsym(_session->gpgme,
        "gpgme_data_release");
    assert(_session->gpg.gpgme_data_release);

    _session->gpg.gpgme_data_identify
        = (gpgme_data_identify_t) (intptr_t) dlsym(_session->gpgme,
        "gpgme_data_identify");
    assert(_session->gpg.gpgme_data_identify);
    _session->gpg.gpgme_data_seek
        = (gpgme_data_seek_t) (intptr_t) dlsym(_session->gpgme,
        "gpgme_data_seek");
    assert(_session->gpg.gpgme_data_seek);

    _session->gpg.gpgme_data_read
        = (gpgme_data_read_t) (intptr_t) dlsym(_session->gpgme,
        "gpgme_data_read");
    assert(_session->gpg.gpgme_data_read);

    _session->gpg.gpgme_op_decrypt
        = (gpgme_op_decrypt_t) (intptr_t) dlsym(_session->gpgme,
        "gpgme_op_decrypt");
    assert(_session->gpg.gpgme_op_decrypt);

    _session->gpg.gpgme_op_verify
        = (gpgme_op_verify_t) (intptr_t) dlsym(_session->gpgme,
        "gpgme_op_verify");
    assert(_session->gpg.gpgme_op_verify);

    _session->gpg.gpgme_op_decrypt_verify
        = (gpgme_op_decrypt_verify_t) (intptr_t) dlsym(_session->gpgme,
        "gpgme_op_decrypt_verify");
    assert(_session->gpg.gpgme_op_decrypt_verify);

    _session->gpg.gpgme_op_decrypt_result
        = (gpgme_op_decrypt_result_t) (intptr_t) dlsym(_session->gpgme,
        "gpgme_op_decrypt_result");
    assert(_session->gpg.gpgme_op_decrypt_result);

    _session->gpg.gpgme_op_encrypt_sign
        = (gpgme_op_encrypt_sign_t) (intptr_t) dlsym(_session->gpgme,
        "gpgme_op_encrypt_sign");
    assert(_session->gpg.gpgme_op_encrypt_sign);

    _session->gpg.gpgme_op_verify_result
        = (gpgme_op_verify_result_t) (intptr_t) dlsym(_session->gpgme,
        "gpgme_op_verify_result");
    assert(_session->gpg.gpgme_op_verify_result);

    _session->gpg.gpgme_signers_clear
        = (gpgme_signers_clear_t) (intptr_t) dlsym(_session->gpgme,
        "gpgme_signers_clear");
    assert(_session->gpg.gpgme_signers_clear);

    _session->gpg.gpgme_signers_add
        = (gpgme_signers_add_t) (intptr_t) dlsym(_session->gpgme,
        "gpgme_signers_add");
    assert(_session->gpg.gpgme_signers_add);
    _session->gpg.gpgme_get_key
        = (gpgme_get_key_t) (intptr_t) dlsym(_session->gpgme, "gpgme_get_key");
    assert(_session->gpg.gpgme_get_key);

    _session->gpg.gpgme_op_genkey
        = (gpgme_op_genkey_t) (intptr_t) dlsym(_session->gpgme,
        "gpgme_op_genkey");
    assert(_session->gpg.gpgme_op_genkey);

    _session->gpg.gpgme_op_genkey_result
        = (gpgme_op_genkey_result_t) (intptr_t) dlsym(_session->gpgme,
        "gpgme_op_genkey_result");
    assert(_session->gpg.gpgme_op_genkey_result);

    _session->gpg.gpgme_op_delete = (gpgme_op_delete_t) (intptr_t)
        dlsym(_session->gpgme, "gpgme_op_delete");
    assert(_session->gpg.gpgme_op_delete);

    _session->gpg.gpgme_op_import = (gpgme_op_import_t) (intptr_t)
        dlsym(_session->gpgme, "gpgme_op_import");
    assert(_session->gpg.gpgme_op_import);

    _session->gpg.gpgme_op_export = (gpgme_op_export_t) (intptr_t)
        dlsym(_session->gpgme, "gpgme_op_export");
    assert(_session->gpg.gpgme_op_export);

    _session->gpg.gpgme_set_keylist_mode = (gpgme_set_keylist_mode_t) (intptr_t)
        dlsym(_session->gpgme, "gpgme_set_keylist_mode");
    assert(_session->gpg.gpgme_set_keylist_mode);

    _session->gpg.gpgme_get_keylist_mode = (gpgme_get_keylist_mode_t) (intptr_t)
        dlsym(_session->gpgme, "gpgme_get_keylist_mode");
    assert(_session->gpg.gpgme_get_keylist_mode);

    _session->gpg.gpgme_op_keylist_start = (gpgme_op_keylist_start_t) (intptr_t)
        dlsym(_session->gpgme, "gpgme_op_keylist_start");
    assert(_session->gpg.gpgme_op_keylist_start);

    _session->gpg.gpgme_op_keylist_next = (gpgme_op_keylist_next_t) (intptr_t)
        dlsym(_session->gpgme, "gpgme_op_keylist_next");
    assert(_session->gpg.gpgme_op_keylist_next);

    _session->gpg.gpgme_op_keylist_end = (gpgme_op_keylist_end_t) (intptr_t)
        dlsym(_session->gpgme, "gpgme_op_keylist_end");
    assert(_session->gpg.gpgme_op_keylist_end);

    _session->gpg.gpgme_op_import_keys = (gpgme_op_import_keys_t) (intptr_t)
        dlsym(_session->gpgme, "gpgme_op_import_keys");
    assert(_session->gpg.gpgme_op_import_keys);

    _session->gpg.gpgme_key_ref = (gpgme_key_ref_t) (intptr_t)
        dlsym(_session->gpgme, "gpgme_key_ref");
    assert(_session->gpg.gpgme_key_ref);

    _session->gpg.gpgme_key_unref = (gpgme_key_unref_t) (intptr_t)
        dlsym(_session->gpgme, "gpgme_key_unref");
    assert(_session->gpg.gpgme_key_unref);

    setlocale(LC_ALL, "");
    _session->version = _session->gpg.gpgme_check(NULL);
    _session->gpg.gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL));

    gpgme_error = _session->gpg.gpgme_new(&_session->ctx);
    gpgme_error = _GPGERR(gpgme_error);
    if (gpgme_error != GPG_ERR_NO_ERROR) {
        dlclose(_session->gpgme);
        free(_session);
        return PEP_INIT_GPGME_INIT_FAILED;
    }
    assert(_session->ctx);

    gpgme_error = _session->gpg.gpgme_set_protocol(_session->ctx,
        GPGME_PROTOCOL_OpenPGP);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error == GPG_ERR_NO_ERROR);

    _session->gpg.gpgme_set_armor(_session->ctx, 1);

    return PEP_STATUS_OK;
}

void pgp_release(PEP_SESSION session)
{
    pEpSession *_session = (pEpSession *) session;
    if (_session->ctx)
        _session->gpg.gpgme_release(_session->ctx);
    _session->ctx = NULL;
    memset(&(_session->gpg), 0, sizeof(struct gpg_s));
    dlclose(_session->gpgme);
}

PEP_STATUS pgp_decrypt_and_verify(
    PEP_SESSION session, const char *ctext, size_t csize,
    char **ptext, size_t *psize, stringlist_t **keylist
    )
{
    pEpSession *_session = (pEpSession *) session;

    PEP_STATUS result;
    gpgme_error_t gpgme_error;
    gpgme_data_t cipher, plain;
    gpgme_data_type_t dt;

    stringlist_t *_keylist = NULL;
    int i_key = 0;

    assert(_session);
    assert(ctext);
    assert(csize);
    assert(ptext);
    assert(psize);
    assert(keylist);

    *ptext = NULL;
    *psize = 0;
    *keylist = NULL;

    gpgme_error = _session->gpg.gpgme_data_new_from_mem(&cipher, ctext, csize, 0);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error == GPG_ERR_NO_ERROR);
    if (gpgme_error != GPG_ERR_NO_ERROR) {
        if (gpgme_error == GPG_ERR_ENOMEM)
            return PEP_OUT_OF_MEMORY;
        else
            return PEP_UNKNOWN_ERROR;
    }

    gpgme_error = _session->gpg.gpgme_data_new(&plain);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error == GPG_ERR_NO_ERROR);
    if (gpgme_error != GPG_ERR_NO_ERROR) {
        _session->gpg.gpgme_data_release(cipher);
        if (gpgme_error == GPG_ERR_ENOMEM)
            return PEP_OUT_OF_MEMORY;
        else
            return PEP_UNKNOWN_ERROR;
    }

    dt = _session->gpg.gpgme_data_identify(cipher);
    switch (dt) {
    case GPGME_DATA_TYPE_PGP_SIGNED:
    case GPGME_DATA_TYPE_PGP_OTHER:
        gpgme_error = _session->gpg.gpgme_op_decrypt_verify(_session->ctx, cipher,
            plain);
        gpgme_error = _GPGERR(gpgme_error);
        assert(gpgme_error != GPG_ERR_INV_VALUE);
        assert(gpgme_error != GPG_ERR_NO_DATA);

        switch (gpgme_error) {
        case GPG_ERR_NO_ERROR:
        {
            gpgme_verify_result_t gpgme_verify_result;
            char *_buffer = NULL;
            size_t reading;
            size_t length = _session->gpg.gpgme_data_seek(plain, 0, SEEK_END);
            gpgme_signature_t gpgme_signature;

            assert(length != -1);
            _session->gpg.gpgme_data_seek(plain, 0, SEEK_SET);

            // TODO: make things less memory consuming
            // the following algorithm allocates memory for the complete
            // text

            _buffer = malloc(length + 1);
            assert(_buffer);
            if (_buffer == NULL) {
                _session->gpg.gpgme_data_release(plain);
                _session->gpg.gpgme_data_release(cipher);
                return PEP_OUT_OF_MEMORY;
            }

            reading = _session->gpg.gpgme_data_read(plain, _buffer, length);
            assert(length == reading);

            gpgme_verify_result =
                _session->gpg.gpgme_op_verify_result(_session->ctx);
            assert(gpgme_verify_result);
            gpgme_signature = gpgme_verify_result->signatures;

            if (gpgme_signature) {
                stringlist_t *k;
                _keylist = new_stringlist(NULL);
                assert(_keylist);
                if (_keylist == NULL) {
                    _session->gpg.gpgme_data_release(plain);
                    _session->gpg.gpgme_data_release(cipher);
                    free(_buffer);
                    return PEP_OUT_OF_MEMORY;
                }
                k = _keylist;

                result = PEP_DECRYPTED_AND_VERIFIED;
                do {
                    switch (gpgme_signature->status) {
                    case GPG_ERR_NO_ERROR:
                        k = stringlist_add(k, gpgme_signature->fpr);
                        break;
                    case GPG_ERR_CERT_REVOKED:
                    case GPG_ERR_BAD_SIGNATURE:
                        result = PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH;
                        break;
                    case GPG_ERR_SIG_EXPIRED:
                    case GPG_ERR_KEY_EXPIRED:
                    case GPG_ERR_NO_PUBKEY:
                        k = stringlist_add(k, gpgme_signature->fpr);
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
        case GPG_ERR_DECRYPT_FAILED:
            result = PEP_DECRYPT_WRONG_FORMAT;
            break;
        case GPG_ERR_BAD_PASSPHRASE:
            NOT_IMPLEMENTED;
        default:
        {
            gpgme_decrypt_result_t gpgme_decrypt_result = _session->gpg.gpgme_op_decrypt_result(_session->ctx);
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

    _session->gpg.gpgme_data_release(plain);
    _session->gpg.gpgme_data_release(cipher);
    return result;
}

PEP_STATUS pgp_verify_text(
    PEP_SESSION session, const char *text, size_t size,
    const char *signature, size_t sig_size, stringlist_t **keylist
    )
{
    pEpSession *_session = (pEpSession *) session;

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

    gpgme_error = _session->gpg.gpgme_data_new_from_mem(&d_text, text, size, 0);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error == GPG_ERR_NO_ERROR);
    if (gpgme_error != GPG_ERR_NO_ERROR) {
        if (gpgme_error == GPG_ERR_ENOMEM)
            return PEP_OUT_OF_MEMORY;
        else
            return PEP_UNKNOWN_ERROR;
    }

    gpgme_error = _session->gpg.gpgme_data_new_from_mem(&d_sig, signature, sig_size, 0);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error == GPG_ERR_NO_ERROR);
    if (gpgme_error != GPG_ERR_NO_ERROR) {
        _session->gpg.gpgme_data_release(d_text);
        if (gpgme_error == GPG_ERR_ENOMEM)
            return PEP_OUT_OF_MEMORY;
        else
            return PEP_UNKNOWN_ERROR;
    }

    gpgme_error = _session->gpg.gpgme_op_verify(_session->ctx, d_sig, d_text, NULL);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error != GPG_ERR_INV_VALUE);

    switch (gpgme_error) {
    case GPG_ERR_NO_ERROR:
    {
        gpgme_verify_result_t gpgme_verify_result;
        gpgme_signature_t gpgme_signature;

        gpgme_verify_result =
            _session->gpg.gpgme_op_verify_result(_session->ctx);
        assert(gpgme_verify_result);
        gpgme_signature = gpgme_verify_result->signatures;

        if (gpgme_signature) {
            stringlist_t *k;
            _keylist = new_stringlist(NULL);
            assert(_keylist);
            if (_keylist == NULL) {
                _session->gpg.gpgme_data_release(d_text);
                _session->gpg.gpgme_data_release(d_sig);
                return PEP_OUT_OF_MEMORY;
            }
            k = _keylist;

            result = PEP_VERIFIED;
            do {
                k = stringlist_add(k, gpgme_signature->fpr);
                if (k == NULL) {
                    free_stringlist(_keylist);
                    _session->gpg.gpgme_data_release(d_text);
                    _session->gpg.gpgme_data_release(d_sig);
                    return PEP_OUT_OF_MEMORY;
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

    _session->gpg.gpgme_data_release(d_text);
    _session->gpg.gpgme_data_release(d_sig);

    return result;
}

PEP_STATUS pgp_encrypt_and_sign(
    PEP_SESSION session, const stringlist_t *keylist, const char *ptext,
    size_t psize, char **ctext, size_t *csize
    )
{
    pEpSession *_session = (pEpSession *) session;

    PEP_STATUS result;
    gpgme_error_t gpgme_error;
    gpgme_data_t plain, cipher;
    gpgme_key_t *rcpt;
    gpgme_encrypt_flags_t flags;
    const stringlist_t *_keylist;
    int i, j;

    assert(_session);
    assert(keylist);
    assert(ptext);
    assert(psize);
    assert(ctext);
    assert(csize);

    *ctext = NULL;
    *csize = 0;

    gpgme_error = _session->gpg.gpgme_data_new_from_mem(&plain, ptext, psize, 0);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error == GPG_ERR_NO_ERROR);
    if (gpgme_error != GPG_ERR_NO_ERROR) {
        if (gpgme_error == GPG_ERR_ENOMEM)
            return PEP_OUT_OF_MEMORY;
        else
            return PEP_UNKNOWN_ERROR;
    }

    gpgme_error = _session->gpg.gpgme_data_new(&cipher);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error == GPG_ERR_NO_ERROR);
    if (gpgme_error != GPG_ERR_NO_ERROR) {
        _session->gpg.gpgme_data_release(plain);
        if (gpgme_error == GPG_ERR_ENOMEM)
            return PEP_OUT_OF_MEMORY;
        else
            return PEP_UNKNOWN_ERROR;
    }

    rcpt = (gpgme_key_t *) calloc(stringlist_length(keylist) + 1,
        sizeof(gpgme_key_t));
    assert(rcpt);
    if (rcpt == NULL) {
        _session->gpg.gpgme_data_release(plain);
        _session->gpg.gpgme_data_release(cipher);
        return PEP_OUT_OF_MEMORY;
    }

    _session->gpg.gpgme_signers_clear(_session->ctx);

    for (_keylist = keylist, i = 0; _keylist != NULL; _keylist = _keylist->next, i++) {
        assert(_keylist->value);
        gpgme_error = _session->gpg.gpgme_get_key(_session->ctx, _keylist->value,
            &rcpt[i], 0);
        gpgme_error = _GPGERR(gpgme_error);
        assert(gpgme_error != GPG_ERR_ENOMEM);

        switch (gpgme_error) {
        case GPG_ERR_ENOMEM:
            for (j = 0; j<i; j++)
                _session->gpg.gpgme_key_unref(rcpt[j]);
            free(rcpt);
            _session->gpg.gpgme_data_release(plain);
            _session->gpg.gpgme_data_release(cipher);
            return PEP_OUT_OF_MEMORY;
        case GPG_ERR_NO_ERROR:
            if (i == 0) {
                gpgme_error_t _gpgme_error = _session->gpg.gpgme_signers_add(_session->ctx, rcpt[0]);
                _gpgme_error = _GPGERR(_gpgme_error);
                assert(_gpgme_error == GPG_ERR_NO_ERROR);
            }
            break;
        case GPG_ERR_EOF:
            for (j = 0; j<i; j++)
                _session->gpg.gpgme_key_unref(rcpt[j]);
            free(rcpt);
            _session->gpg.gpgme_data_release(plain);
            _session->gpg.gpgme_data_release(cipher);
            return PEP_KEY_NOT_FOUND;
        case GPG_ERR_AMBIGUOUS_NAME:
            for (j = 0; j<i; j++)
                _session->gpg.gpgme_key_unref(rcpt[j]);
            free(rcpt);
            _session->gpg.gpgme_data_release(plain);
            _session->gpg.gpgme_data_release(cipher);
            return PEP_KEY_HAS_AMBIG_NAME;
        default: // GPG_ERR_INV_VALUE if CTX or R_KEY is not a valid pointer or
            // FPR is not a fingerprint or key ID
            for (j = 0; j<i; j++)
                _session->gpg.gpgme_key_unref(rcpt[j]);
            free(rcpt);
            _session->gpg.gpgme_data_release(plain);
            _session->gpg.gpgme_data_release(cipher);
            return PEP_GET_KEY_FAILED;
        }
    }

    // TODO: remove that and replace with proper key management
    flags = GPGME_ENCRYPT_ALWAYS_TRUST;

    gpgme_error = _session->gpg.gpgme_op_encrypt_sign(_session->ctx, rcpt, flags,
        plain, cipher);
    gpgme_error = _GPGERR(gpgme_error);
    switch (gpgme_error) {
    case GPG_ERR_NO_ERROR:
    {
        char *_buffer = NULL;
        size_t reading;
        size_t length = _session->gpg.gpgme_data_seek(cipher, 0, SEEK_END);
        assert(length != -1);
        _session->gpg.gpgme_data_seek(cipher, 0, SEEK_SET);

        // TODO: make things less memory consuming
        // the following algorithm allocates a buffer for the complete text

        _buffer = (char *) malloc(length + 1);
        assert(_buffer);
        if (_buffer == NULL) {
            for (j = 0; j<stringlist_length(keylist); j++)
                _session->gpg.gpgme_key_unref(rcpt[j]);
            free(rcpt);
            _session->gpg.gpgme_data_release(plain);
            _session->gpg.gpgme_data_release(cipher);
            return PEP_OUT_OF_MEMORY;
        }

        reading = _session->gpg.gpgme_data_read(cipher, _buffer, length);
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
        _session->gpg.gpgme_key_unref(rcpt[j]);
    free(rcpt);
    _session->gpg.gpgme_data_release(plain);
    _session->gpg.gpgme_data_release(cipher);
    return result;
}

PEP_STATUS pgp_generate_keypair(
    PEP_SESSION session, pEp_identity *identity
    )
{
    pEpSession *_session = (pEpSession *) session;
    gpgme_error_t gpgme_error;
    char *parms;
    const char *template =
        "<GnupgKeyParms format=\"internal\">\n"
        "Key-Type: RSA\n"
        "Key-Length: 4096\n"
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
    assert(identity->fpr == NULL);
    assert(identity->username);

    parms = calloc(1, PARMS_MAX);
    assert(parms);
    if (parms == NULL)
        return PEP_OUT_OF_MEMORY;

    result = snprintf(parms, PARMS_MAX, template, identity->username,
        identity->address); // , _session->passphrase);
    assert(result < PARMS_MAX);
    if (result >= PARMS_MAX) {
        free(parms);
        return PEP_BUFFER_TOO_SMALL;
    }

    gpgme_error = _session->gpg.gpgme_op_genkey(_session->ctx, parms, NULL, NULL);
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

    gpgme_genkey_result = _session->gpg.gpgme_op_genkey_result(_session->ctx);
    assert(gpgme_genkey_result);
    assert(gpgme_genkey_result->fpr);

    identity->fpr = strdup(gpgme_genkey_result->fpr);

    return PEP_STATUS_OK;
}

PEP_STATUS pgp_delete_keypair(PEP_SESSION session, const char *fpr)
{
    pEpSession *_session = (pEpSession *) session;
    gpgme_error_t gpgme_error;
    gpgme_key_t key;

    assert(session);
    assert(fpr);

    gpgme_error = _session->gpg.gpgme_get_key(_session->ctx, fpr, &key, 0);
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

    gpgme_error = _session->gpg.gpgme_op_delete(_session->ctx, key, 1);
    gpgme_error = _GPGERR(gpgme_error);
    _session->gpg.gpgme_key_unref(key);
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

PEP_STATUS pgp_import_key(PEP_SESSION session, const char *key_data, size_t size)
{
    pEpSession *_session = (pEpSession *) session;
    gpgme_error_t gpgme_error;
    gpgme_data_t dh;

    assert(session);
    assert(key_data);

    gpgme_error = _session->gpg.gpgme_data_new_from_mem(&dh, key_data, size, 0);
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

    gpgme_error = _session->gpg.gpgme_op_import(_session->ctx, dh);
    gpgme_error = _GPGERR(gpgme_error);
    switch (gpgme_error) {
    case GPG_ERR_NO_ERROR:
        break;
    case GPG_ERR_INV_VALUE:
        assert(0);
        _session->gpg.gpgme_data_release(dh);
        return PEP_UNKNOWN_ERROR;
    case GPG_ERR_NO_DATA:
        _session->gpg.gpgme_data_release(dh);
        return PEP_ILLEGAL_VALUE;
    default:
        assert(0);
        _session->gpg.gpgme_data_release(dh);
        return PEP_UNKNOWN_ERROR;
    }

    _session->gpg.gpgme_data_release(dh);
    return PEP_STATUS_OK;
}

PEP_STATUS pgp_export_key(
    PEP_SESSION session, const char *fpr, char **key_data, size_t *size
    )
{
    pEpSession *_session = (pEpSession *) session;
    gpgme_error_t gpgme_error;
    gpgme_data_t dh;
    size_t _size;
    char *buffer;
    int reading;

    assert(session);
    assert(fpr);
    assert(key_data);
    assert(size);

    gpgme_error = _session->gpg.gpgme_data_new(&dh);
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

    gpgme_error = _session->gpg.gpgme_op_export(_session->ctx, fpr,
        GPGME_EXPORT_MODE_MINIMAL, dh);
    gpgme_error = _GPGERR(gpgme_error);
    switch (gpgme_error) {
    case GPG_ERR_NO_ERROR:
        break;
    case GPG_ERR_EOF:
        _session->gpg.gpgme_data_release(dh);
        return PEP_KEY_NOT_FOUND;
    case GPG_ERR_INV_VALUE:
        assert(0);
        _session->gpg.gpgme_data_release(dh);
        return PEP_UNKNOWN_ERROR;
    default:
        assert(0);
        _session->gpg.gpgme_data_release(dh);
        return PEP_UNKNOWN_ERROR;
    };

    _size = _session->gpg.gpgme_data_seek(dh, 0, SEEK_END);
    assert(_size != -1);
    _session->gpg.gpgme_data_seek(dh, 0, SEEK_SET);

    buffer = malloc(_size + 1);
    assert(buffer);
    if (buffer == NULL) {
        _session->gpg.gpgme_data_release(dh);
        return PEP_OUT_OF_MEMORY;
    }

    reading = _session->gpg.gpgme_data_read(dh, buffer, _size);
    assert(_size == reading);

    // safeguard for the naive user
    buffer[_size] = 0;

    *key_data = buffer;
    *size = _size;

    _session->gpg.gpgme_data_release(dh);
    return PEP_STATUS_OK;
}

static void _switch_mode(pEpSession *_session, gpgme_keylist_mode_t remove_mode,
    gpgme_keylist_mode_t add_mode)
{
    gpgme_error_t gpgme_error;
    gpgme_keylist_mode_t mode;

    mode = _session->gpg.gpgme_get_keylist_mode(_session->ctx);

    mode &= ~remove_mode;
    mode |= add_mode;

    gpgme_error = _session->gpg.gpgme_set_keylist_mode(_session->ctx, mode);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error == GPG_ERR_NO_ERROR);
}

PEP_STATUS pgp_recv_key(PEP_SESSION session, const char *pattern)
{
    pEpSession *_session = (pEpSession *) session;
    gpgme_error_t gpgme_error;
    gpgme_key_t key;

    assert(session);
    assert(pattern);

    _switch_mode(_session, GPGME_KEYLIST_MODE_LOCAL, GPGME_KEYLIST_MODE_EXTERN);

    gpgme_error = _session->gpg.gpgme_op_keylist_start(_session->ctx, pattern, 0);
    gpgme_error = _GPGERR(gpgme_error);
    switch (gpgme_error) {
    case GPG_ERR_NO_ERROR:
        break;
    case GPG_ERR_INV_VALUE:
        assert(0);
        _switch_mode(_session, GPGME_KEYLIST_MODE_EXTERN,
            GPGME_KEYLIST_MODE_LOCAL);
        return PEP_UNKNOWN_ERROR;
    default:
        _switch_mode(_session, GPGME_KEYLIST_MODE_EXTERN,
            GPGME_KEYLIST_MODE_LOCAL);
        return PEP_GET_KEY_FAILED;
    };

    do {
        gpgme_error = _session->gpg.gpgme_op_keylist_next(_session->ctx, &key);
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

            gpgme_error = _session->gpg.gpgme_op_import_keys(_session->ctx, keys);
            gpgme_error = _GPGERR(gpgme_error);
            _session->gpg.gpgme_key_unref(key);
            assert(gpgme_error != GPG_ERR_INV_VALUE);
            assert(gpgme_error != GPG_ERR_CONFLICT);
        }
            break;
        case GPG_ERR_ENOMEM:
            _switch_mode(_session, GPGME_KEYLIST_MODE_EXTERN,
                GPGME_KEYLIST_MODE_LOCAL);
            _session->gpg.gpgme_op_keylist_end(_session->ctx);
            return PEP_OUT_OF_MEMORY;
        default:
            // BUG: GPGME returns an illegal value instead of GPG_ERR_EOF after
            // reading first key
#ifndef NDEBUG
            fprintf(stderr, "warning: unknown result 0x%x of"
                " gpgme_op_keylist_next()\n", gpgme_error);
#endif
            gpgme_error = GPG_ERR_EOF;
            break;
        };
    } while (gpgme_error != GPG_ERR_EOF);

    _session->gpg.gpgme_op_keylist_end(_session->ctx);
    _switch_mode(_session, GPGME_KEYLIST_MODE_EXTERN,
        GPGME_KEYLIST_MODE_LOCAL);
    return PEP_STATUS_OK;
}

PEP_STATUS pgp_find_keys(
    PEP_SESSION session, const char *pattern, stringlist_t **keylist
    )
{
    pEpSession *_session = (pEpSession *) session;
    gpgme_error_t gpgme_error;
    gpgme_key_t key;
    stringlist_t *_keylist;
    char *fpr;

    assert(session);
    assert(pattern);
    assert(keylist);

    *keylist = NULL;

    gpgme_error = _session->gpg.gpgme_op_keylist_start(_session->ctx, pattern, 0);
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

    _keylist = new_stringlist(NULL);
    stringlist_t *_k = _keylist;

    do {
        gpgme_error = _session->gpg.gpgme_op_keylist_next(_session->ctx, &key);
        gpgme_error = _GPGERR(gpgme_error);
        assert(gpgme_error != GPG_ERR_INV_VALUE);
        switch (gpgme_error) {
        case GPG_ERR_EOF:
            break;
        case GPG_ERR_NO_ERROR:
            assert(key);
            assert(key->subkeys);
            fpr = key->subkeys->fpr;
            assert(fpr);
            _k = stringlist_add(_k, fpr);
            assert(_k);
            if (_k != NULL)
                break;
        case GPG_ERR_ENOMEM:
            free_stringlist(_keylist);
            _session->gpg.gpgme_op_keylist_end(_session->ctx);
            return PEP_OUT_OF_MEMORY;
        default:
            // BUG: GPGME returns an illegal value instead of GPG_ERR_EOF after
            // reading first key
#ifndef NDEBUG
            fprintf(stderr, "warning: unknown result 0x%x of"
                " gpgme_op_keylist_next()\n", gpgme_error);
#endif
            gpgme_error = GPG_ERR_EOF;
            break;
        };
    } while (gpgme_error != GPG_ERR_EOF);

    _session->gpg.gpgme_op_keylist_end(_session->ctx);
    *keylist = _keylist;
    return PEP_STATUS_OK;
}

PEP_STATUS pgp_send_key(PEP_SESSION session, const char *pattern)
{
    pEpSession *_session = (pEpSession *) session;
    gpgme_error_t gpgme_error;

    assert(session);
    assert(pattern);

    gpgme_error = _session->gpg.gpgme_op_export(_session->ctx, pattern,
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
    pEpSession *_session = (pEpSession *) session;
    PEP_STATUS status = PEP_STATUS_OK;
    gpgme_error_t gpgme_error;
    gpgme_key_t key;

    assert(session);
    assert(fpr);
    assert(comm_type);

    *comm_type = PEP_ct_unknown;

    gpgme_error = _session->gpg.gpgme_op_keylist_start(_session->ctx, fpr, 0);
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

    gpgme_error = _session->gpg.gpgme_op_keylist_next(_session->ctx, &key);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error != GPG_ERR_INV_VALUE);

    if (key == NULL) {
        _session->gpg.gpgme_op_keylist_end(_session->ctx);
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
        _session->gpg.gpgme_op_keylist_end(_session->ctx);
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
                *comm_type = PEP_ct_OpenPGP_1024_RSA_unconfirmed;

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
        _session->gpg.gpgme_op_keylist_end(_session->ctx);
        *comm_type = PEP_ct_unknown;
        return PEP_OUT_OF_MEMORY;
    default:
        // BUG: GPGME returns an illegal value instead of GPG_ERR_EOF after
        // reading first key
#ifndef NDEBUG
        fprintf(stderr, "warning: unknown result 0x%x of"
            " gpgme_op_keylist_next()\n", gpgme_error);
#endif
        gpgme_error = GPG_ERR_EOF;
        break;
    };

    _session->gpg.gpgme_op_keylist_end(_session->ctx);

    return status;
}
