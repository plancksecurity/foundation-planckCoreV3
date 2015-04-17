#include "pEp_internal.h"
#include "pgp_netpgp.h"

#include <limits.h>

#include "wrappers.h"

#include <netpgp.h>
#include <netpgp/config.h>
#include <netpgp/memory.h>
#include <netpgp/crypto.h>
#include <netpgp/netpgpsdk.h>
#include <netpgp/validate.h>

#include <regex.h>

#define PEP_NETPGP_DEBUG

PEP_STATUS pgp_init(PEP_SESSION session, bool in_first)
{
    netpgp_t *netpgp;
    PEP_STATUS status = PEP_STATUS_OK;
    const char *home = NULL;

    assert(session);
    if(!session) return PEP_UNKNOWN_ERROR;

    netpgp = &session->ctx;
   
    if (in_first) {
        if (strcmp(setlocale(LC_ALL, NULL), "C") == 0)
            setlocale(LC_ALL, "");
    }

    memset(netpgp, 0x0, sizeof(session->ctx));

    // netpgp_setvar(netpgp, "max mem alloc", "4194304");
    netpgp_setvar(netpgp, "need seckey", "1");
    netpgp_setvar(netpgp, "need userid", "1");

    // NetPGP shares home with GPG
    home = gpg_home();
    if(home){
        netpgp_set_homedir(netpgp,(char*)home, NULL, 0);
    }else{
        status = PEP_INIT_NO_GPG_HOME;
        goto pep_error;
    }

    // pair with gpg's cert-digest-algo
    netpgp_setvar(netpgp, "hash", "SHA256");

    // subset of gpg's personal-cipher-preferences
    // here only one cipher can be selected
    netpgp_setvar(netpgp, "cipher", "AES256");

    if (!netpgp_init(netpgp)) {
        status = PEP_INIT_NETPGP_INIT_FAILED;
        goto pep_error;
    }

    return PEP_STATUS_OK;

pep_error:
    pgp_release(session, in_first);
    return status;
}

void pgp_release(PEP_SESSION session, bool out_last)
{
    netpgp_t *netpgp;

    assert(session);
    if(!session) return;

    netpgp = &session->ctx;

    netpgp_end(netpgp);
    memset(netpgp, 0x0, sizeof(session->ctx));

    // out_last unused here
}

// return 1 if the file contains ascii-armoured text 
// buf MUST be \0 terminated to be checked for armour
static unsigned
_armoured(const char *buf, size_t size, const char *pattern)
{
    unsigned armoured = 0;
    if(buf[size]=='\0'){
        regex_t r;
        regcomp(&r, pattern, REG_EXTENDED|REG_NEWLINE|REG_NOSUB);
        if (regexec(&r, buf, 0, NULL, 0) == 0) {
            armoured = 1;
        }
        regfree(&r);
    }
    return armoured;
}

// Iterate through netpgp' reported valid signatures 
// fill a list of valid figerprints
// returns PEP_STATUS_OK if all sig reported valid
// error status otherwise.
static PEP_STATUS _validation_results(netpgp_t *netpgp, pgp_validation_t *vresult,
                                             stringlist_t **_keylist)
{
    time_t    now;
    time_t    t;
    char    buf[128];

    now = time(NULL);
    if (now < vresult->birthtime) {
        // signature is not valid yet
#ifdef PEP_NETPGP_DEBUG
        (void) printf(
            "signature not valid until %.24s\n",
            ctime(&vresult->birthtime));
#endif //PEP_NETPGP_DEBUG
        return PEP_UNENCRYPTED;
    }
    if (vresult->duration != 0 && now > vresult->birthtime + vresult->duration) {
        // signature has expired
        t = vresult->duration + vresult->birthtime;
#ifdef PEP_NETPGP_DEBUG
        (void) printf(
            "signature not valid after %.24s\n",
            ctime(&t));
#endif //PEP_NETPGP_DEBUG
        return PEP_UNENCRYPTED;
    }
    if (vresult->validc && vresult->valid_sigs &&
        !vresult->invalidc && !vresult->unknownc ) {
        unsigned    n;
        stringlist_t *k;
        // caller responsible to free
        *_keylist = new_stringlist(NULL);
        assert(*_keylist);
        if (*_keylist == NULL) {
            return PEP_OUT_OF_MEMORY;
        }
        k = *_keylist;
        for (n = 0; n < vresult->validc; ++n) {
            int i;
            char id[MAX_ID_LENGTH + 1];
            static const char *hexes = "0123456789abcdef";
            const uint8_t *userid = vresult->valid_sigs[n].signer_id;

#ifdef PEP_NETPGP_DEBUG
            const pgp_key_t *key;
            pgp_pubkey_t *sigkey;
            unsigned from = 0;
            key = pgp_getkeybyid(netpgp->io, netpgp->pubring,
                (const uint8_t *) vresult->valid_sigs[n].signer_id,
                &from, &sigkey);
            pgp_print_keydata(netpgp->io, netpgp->pubring, key, "valid signature ", &key->key.pubkey, 0);
#endif //PEP_NETPGP_DEBUG

            for (i = 0; i < 8 ; i++) {
                id[i * 2] = hexes[(unsigned)(userid[i] & 0xf0) >> 4];
                id[(i * 2) + 1] = hexes[userid[i] & 0xf];
            }
            id[8 * 2] = 0x0;

            k = stringlist_add(k, id);
            if(!k){
                free_stringlist(*_keylist);
                return PEP_OUT_OF_MEMORY;
            }
        }
        return PEP_STATUS_OK;
    }
    if (vresult->validc + vresult->invalidc + vresult->unknownc == 0) {
        // No signatures found - is this memory signed?
        return PEP_VERIFY_NO_KEY; 
    } 
    
    if (vresult->invalidc) {
        // some invalid signatures

#ifdef PEP_NETPGP_DEBUG
        unsigned    n;
        for (n = 0; n < vresult->invalidc; ++n) {
            const pgp_key_t *key;
            pgp_pubkey_t *sigkey;
            unsigned from = 0;
            key = pgp_getkeybyid(netpgp->io, netpgp->pubring,
                (const uint8_t *) vresult->invalid_sigs[n].signer_id,
                &from, &sigkey);
            pgp_print_keydata(netpgp->io, netpgp->pubring, key, "invalid signature ", &key->key.pubkey, 0);
            if (sigkey->duration != 0 && now > sigkey->birthtime + sigkey->duration) {
                printf("EXPIRED !\n");
            }
        }
#endif //PEP_NETPGP_DEBUG

        return PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH;
    }
    
    // only unknown sigs
    return PEP_DECRYPT_WRONG_FORMAT;
}

#define ARMOR_HEAD    "^-----BEGIN PGP MESSAGE-----\\s*$"
PEP_STATUS pgp_decrypt_and_verify(
    PEP_SESSION session, const char *ctext, size_t csize,
    char **ptext, size_t *psize, stringlist_t **keylist
    )
{
    netpgp_t *netpgp;
    pgp_memory_t *mem;
    pgp_memory_t *cat;
    pgp_validation_t *vresult;
    char *_ptext = NULL;
    size_t _psize = 0;
    int ret;

    PEP_STATUS result;
    stringlist_t *_keylist = NULL;
    int i_key = 0;

    assert(session);
    assert(ctext);
    assert(csize);
    assert(ptext);
    assert(psize);
    assert(keylist);

    if(!session || !ctext || !csize || !ptext || !psize || !keylist) 
        return PEP_UNKNOWN_ERROR;

    netpgp = &session->ctx;

    *ptext = NULL;
    *psize = 0;
    *keylist = NULL;

    vresult = malloc(sizeof(pgp_validation_t));
    memset(vresult, 0x0, sizeof(pgp_validation_t));

    mem = pgp_decrypt_and_validate_buf(netpgp->io, vresult, ctext, csize,
                netpgp->secring, netpgp->pubring,
                _armoured(ctext, csize, ARMOR_HEAD),
                0 /* sshkeys */,
                NULL, -1, NULL  /* pass fp,attempts,cb */);
    if (mem == NULL) {
        return PEP_OUT_OF_MEMORY;
    }

    _psize = pgp_mem_len(mem);
    if (_psize){
        if ((_ptext = calloc(1, _psize)) == NULL) {
            result = PEP_OUT_OF_MEMORY;
            goto free_pgp;
        }
        memcpy(_ptext, pgp_mem_data(mem), _psize);
        result = PEP_DECRYPTED;
    }else{
        result = PEP_DECRYPT_NO_KEY;
        goto free_pgp;
    }

    if (result == PEP_DECRYPTED) {
        result = _validation_results(netpgp, vresult, &_keylist);
        if (result != PEP_STATUS_OK) {
            goto free_ptext;
        }
        result = PEP_DECRYPTED_AND_VERIFIED;
    }

    if (result == PEP_DECRYPTED_AND_VERIFIED
        || result == PEP_DECRYPTED) {
        *ptext = _ptext;
        *psize = _psize;
        (*ptext)[*psize] = 0; // safeguard for naive users
        if (result == PEP_DECRYPTED_AND_VERIFIED) {
            *keylist = _keylist;
        }

        /* _ptext and _keylist ownership transfer, don't free */
        goto free_pgp;
    }

free_keylist:
    free_stringlist(_keylist);

free_ptext:
    free(_ptext);

free_pgp:
    pgp_memory_free(mem);
    pgp_validate_result_free(vresult);

    return result;
}

#define ARMOR_SIG_HEAD    "^-----BEGIN PGP (SIGNATURE|SIGNED MESSAGE)-----\\s*$"
PEP_STATUS pgp_verify_text(
    PEP_SESSION session, const char *text, size_t size,
    const char *signature, size_t sig_size, stringlist_t **keylist
    )
{
    netpgp_t *netpgp;
    pgp_memory_t *signedmem;
    pgp_memory_t *sig;
    pgp_validation_t *vresult;

    PEP_STATUS result;
    stringlist_t *_keylist;

    assert(session);
    assert(text);
    assert(size);
    assert(signature);
    assert(sig_size);
    assert(keylist);

    if(!session || !text || !size || !signature || !sig_size || !keylist) 
        return PEP_UNKNOWN_ERROR;

    netpgp = &session->ctx;

    *keylist = NULL;

    vresult = malloc(sizeof(pgp_validation_t));
    memset(vresult, 0x0, sizeof(pgp_validation_t));

    signedmem = pgp_memory_new();
    if (signedmem == NULL) {
        return PEP_OUT_OF_MEMORY;
    }
    pgp_memory_add(signedmem, (const uint8_t*)text, size);

    sig = pgp_memory_new();
    if (sig == NULL) {
        pgp_memory_free(signedmem);
        return PEP_OUT_OF_MEMORY;
    }
    pgp_memory_add(sig, (const uint8_t*)signature, sig_size);

    pgp_validate_mem_detached(netpgp->io, vresult, sig,
                NULL,/* output */
                _armoured(signature, sig_size, ARMOR_SIG_HEAD),
                netpgp->pubring,
                signedmem);

    result = _validation_results(netpgp, vresult, &_keylist);
    if (result != PEP_STATUS_OK) {
        goto free_pgp;
    }else{
        result = PEP_VERIFIED;
    }

    if (result == PEP_VERIFIED) {
        /* TODO : check trust level */
        result = PEP_VERIFIED_AND_TRUSTED;
    }

    if (result == PEP_VERIFIED || result == PEP_VERIFIED_AND_TRUSTED) {
        *keylist = _keylist;

        /* _keylist ownership transfer, don't free */
        goto free_pgp;
    }

free_keylist:
    free_stringlist(_keylist);

free_pgp:
    // free done by pgp_validate_mem_detached
    // pgp_memory_free(sig);
    // pgp_memory_free(signedmem);
    pgp_validate_result_free(vresult);

    return result;
}

PEP_STATUS pgp_encrypt_and_sign(
    PEP_SESSION session, const stringlist_t *keylist, const char *ptext,
    size_t psize, char **ctext, size_t *csize
    )
{
    netpgp_t *netpgp;
    const pgp_key_t *keypair;
    pgp_seckey_t *seckey;
	pgp_memory_t *signedmem;
    const char *userid;
    const char *hashalg;

    PEP_STATUS result;
    const stringlist_t *_keylist;
    int i;

    assert(session);
    assert(keylist);
    assert(ptext);
    assert(psize);
    assert(ctext);
    assert(csize);

    if(!session || !ptext || !psize || !ctext || !csize || !keylist) 
        return PEP_UNKNOWN_ERROR;

    *ctext = NULL;
    *csize = 0;

    // Get signing details from netpgp
    if ((userid = netpgp_getvar(netpgp, "userid")) == NULL || 
        (keypair = pgp_getkeybyname(netpgp->io, netpgp->secring, userid)) == NULL ||
        (seckey = pgp_decrypt_seckey(keypair, NULL /*passfp*/)) == NULL) {
        return PEP_UNKNOWN_ERROR;
    }
    hashalg = netpgp_getvar(netpgp, "hash");
    if (seckey->pubkey.alg == PGP_PKA_DSA) {
    	hashalg = "sha1";
    }

    // Sign data
    signedmem = pgp_sign_buf(netpgp->io, ptext, psize, seckey,
    			time(NULL), /* birthtime */
    			0 /* duration */,
    			hashalg, 
                0 /* armored */,
                0 /* cleartext */);

    pgp_forget(seckey, (unsigned)sizeof(*seckey));

    if (!signedmem) {
        return PEP_UNENCRYPTED;
    }

    // Encrypt signed data
    pgp_memory_free(signedmem);
    result = PEP_UNKNOWN_ERROR;
    return result;
/*
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 * */
    for (_keylist = keylist, i = 0; _keylist != NULL; _keylist = _keylist->next, i++) {
        assert(_keylist->value);
        /* TODO */
        /* get key from  _keylist->value */
        /* add key to recipients/signers */
    }

    /* Do encrypt and sign */ 
    char *_buffer = NULL;
    size_t length = /* TODO length*/ 0;
    assert(length != -1);

    /* Allocate transferable buffer */
    _buffer = malloc(length + 1);
    assert(_buffer);
    if (_buffer == NULL) {
        /* TODO clean */
        return PEP_OUT_OF_MEMORY;
    }

    *ctext = _buffer;
    *csize = length;
    (*ctext)[*csize] = 0; // safeguard for naive users
    result = PEP_STATUS_OK;

    
    result = PEP_UNKNOWN_ERROR;
    return result;
}

PEP_STATUS pgp_generate_keypair(
    PEP_SESSION session, pEp_identity *identity
    )
{
    char *parms;
    const char *template =
        "Key-Type: RSA\n"
        "Key-Length: 4096\n"
        "Name-Real: %s\n"
        "Name-Email: %s\n"
        /* "Passphrase: %s\n" */
        "Expire-Date: 1y\n";
    int result;

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
        identity->address);
    assert(result < PARMS_MAX);
    if (result >= PARMS_MAX) {
        free(parms);
        return PEP_BUFFER_TOO_SMALL;
    }

    /* TODO generate key */

    free(parms);

        return PEP_UNKNOWN_ERROR;
        return PEP_ILLEGAL_VALUE;
        return PEP_CANNOT_CREATE_KEY;

    identity->fpr = strdup("TODO generated key fpr");

    return PEP_STATUS_OK;
}

PEP_STATUS pgp_delete_keypair(PEP_SESSION session, const char *fpr)
{
    assert(session);
    assert(fpr);

    /* TODO get key with given fpr */
        return PEP_KEY_NOT_FOUND;
        return PEP_ILLEGAL_VALUE;
        return PEP_KEY_HAS_AMBIG_NAME;
        return PEP_OUT_OF_MEMORY;
        return PEP_UNKNOWN_ERROR;

    /* TODO delete that key */
        return PEP_UNKNOWN_ERROR;
        return PEP_KEY_NOT_FOUND;
        return PEP_KEY_HAS_AMBIG_NAME;
        return PEP_UNKNOWN_ERROR;

    return PEP_STATUS_OK;
}

PEP_STATUS pgp_import_keydata(PEP_SESSION session, const char *key_data, size_t size)
{
    assert(session);
    assert(key_data);

    /* TODO import */
        return PEP_UNKNOWN_ERROR;
        return PEP_ILLEGAL_VALUE;
        return PEP_UNKNOWN_ERROR;
    return PEP_STATUS_OK;
}

PEP_STATUS pgp_export_keydata(
    PEP_SESSION session, const char *fpr, char **key_data, size_t *size
    )
{
    size_t _size;
    char *buffer;
    int reading;

    assert(session);
    assert(fpr);
    assert(key_data);
    assert(size);


    /* TODO export */
        return PEP_KEY_NOT_FOUND;
        return PEP_UNKNOWN_ERROR;
        return PEP_UNKNOWN_ERROR;

    _size = /* TODO */ 0;
    assert(_size != -1);

    buffer = malloc(_size + 1);
    assert(buffer);
    if (buffer == NULL) {
        /* TODO clean */
        return PEP_OUT_OF_MEMORY;
    }

    // safeguard for the naive user
    buffer[_size] = 0;

    *key_data = buffer;
    *size = _size;

    return PEP_STATUS_OK;
}

// "keyserver"
// "hkp://keys.gnupg.net"
PEP_STATUS pgp_recv_key(PEP_SESSION session, const char *pattern)
{
    assert(session);
    assert(pattern);

    /* TODO ask for key */
        return PEP_UNKNOWN_ERROR;
        return PEP_GET_KEY_FAILED;

    do {

        /* For each key */
        /* import key */
    } while (0);

    return PEP_STATUS_OK;
}

PEP_STATUS pgp_find_keys(
    PEP_SESSION session, const char *pattern, stringlist_t **keylist
    )
{
    stringlist_t *_keylist;
    char *fpr;

    assert(session);
    assert(pattern);
    assert(keylist);

    *keylist = NULL;

    /* Ask for key */
        return PEP_UNKNOWN_ERROR;
        return PEP_GET_KEY_FAILED;

    _keylist = new_stringlist(NULL);
    stringlist_t *_k = _keylist;

    do {
            fpr = "TODO key->subkeys->fpr";
            assert(fpr);
            _k = stringlist_add(_k, fpr);
            assert(_k);
            if (_k == NULL){
                free_stringlist(_keylist);
                return PEP_OUT_OF_MEMORY;
            }
    } while (0);

    *keylist = _keylist;
    return PEP_STATUS_OK;
}

PEP_STATUS pgp_send_key(PEP_SESSION session, const char *pattern)
{
    assert(session);
    assert(pattern);

    /* TODO send key */

        return PEP_CANNOT_SEND_KEY;
        return PEP_STATUS_OK;
}


PEP_STATUS pgp_get_key_rating(
    PEP_SESSION session,
    const char *fpr,
    PEP_comm_type *comm_type
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);
    assert(fpr);
    assert(comm_type);

    *comm_type = PEP_ct_unknown;

    /* TODO get key from fpr */
    return PEP_UNKNOWN_ERROR;
    return PEP_GET_KEY_FAILED;

    switch (/*TODO key->protocol*/ 4) {
    case /* TODO  OpenPGP */0:
    case /* TODO DEFAULT */1:
        *comm_type = PEP_ct_OpenPGP_unconfirmed;
        break;
    case /* TODO CMS */2:
        *comm_type = PEP_ct_CMS_unconfirmed;
        break;
    default:
        *comm_type = PEP_ct_unknown;
        return PEP_STATUS_OK;
    }

        for (; 1 == 0; /* Each subkeys */ ) {
            if (/* TODO length */0 < 1024)
                *comm_type = PEP_ct_key_too_short;
            else if (
                (
                (   /* TODO pubkey_algo == RSA  */ 0)
                || (/* TODO pubkey_algo == RSA_E*/ 0)
                || (/* TODO pubkey_algo == RSA_S*/ 0)
                )
                && /* sk->length */0 == 1024
                )
                *comm_type = PEP_ct_OpenPGP_weak_unconfirmed;

            if (/* TODO invalid */ 1) {
                *comm_type = PEP_ct_key_b0rken;
                break;
            }
            if (/* TODO expired */ 1) {
                *comm_type = PEP_ct_key_expired;
                break;
            }
            if (/* TODO revoked*/ 1) {
                *comm_type = PEP_ct_key_revoked;
                break;
            }
        }
        *comm_type = PEP_ct_unknown;
        return PEP_OUT_OF_MEMORY;
        return PEP_UNKNOWN_ERROR;


    return status;
}
