/**
 * @internal
 * @file pgp_netpgp.c
 * @brief Implementation of NetPGP
 * @license This file is under GNU General Public License 3.0 see LICENSE.txt
 */

/*
* Check to see if this machine uses EBCDIC.  (Yes, believe it or
* not, there are still machines out there that use EBCDIC.)
*/
#if 'A' == '\301'
# define NETPGP_EBCDIC 1
#else
# define NETPGP_ASCII 1
#endif

#include "pEp_internal.h"
#include "pgp_netpgp.h"

#include <limits.h>
#include <ctype.h>

#include "wrappers.h"

#include <netpgp.h>

#include <netpgp/config.h>
#include <netpgp/memory.h>
#include <netpgp/crypto.h>
#include <netpgp/netpgpsdk.h>
#include <netpgp/validate.h>
#include <netpgp/readerwriter.h>
#include <netpgp/netpgpdefs.h>

#include <pthread.h>
#include <regex.h>
#if defined(NETPGP_EBCDIC)
#include <unistd.h>
#endif

#if 0
#define TRACE_FUNCS() printf("Trace fun: %s:%d, %s\n",__FILE__,__LINE__,__FUNCTION__);
#else
#define TRACE_FUNCS()
#endif

#define _ENDL "\\s*(\r\n|\r|\n)"

inline char A(char c)
{
    TRACE_FUNCS()
#if defined(NETPGP_EBCDIC)
    __e2a_l(&c,1);
#endif
    return c;
}

netpgp_t *netpgp;
static pthread_mutex_t netpgp_mutex;

static PEP_STATUS init_netpgp()
{
    TRACE_FUNCS()
    PEP_STATUS status = PEP_STATUS_OK;
    const char *home = NULL;
    pgp_io_t *io;

    if(pthread_mutex_init(&netpgp_mutex, NULL)){
        return PEP_OUT_OF_MEMORY;
    }

    if(pthread_mutex_lock(&netpgp_mutex)){
        return PEP_UNKNOWN_ERROR;
    }

    if (strcmp(setlocale(LC_ALL, NULL), "C") == 0)
        setlocale(LC_ALL, "");

    netpgp=malloc(sizeof(netpgp_t));
    memset(netpgp, 0x0, sizeof(netpgp_t));

    //netpgp_setvar(netpgp, "max mem alloc", "4194304");
    netpgp_setvar(netpgp, "need seckey", "1");
    netpgp_setvar(netpgp, "need pubkey", "1");
    netpgp_setvar(netpgp, "batch", "1");

    //pgp_set_debug_level("keyring.c");
    //netpgp_setvar(netpgp, "need userid", "1");

    if (!home)
        home = getenv("HOME");

    if (!home)
        status = PEP_INIT_CRYPTO_LIB_INIT_FAILED;
    
    if(home){
        netpgp_set_homedir(netpgp,(char*)home, "/.netpgp", 0);
    }else{
        status = PEP_INIT_NO_CRYPTO_HOME;
        goto unlock_netpgp;
    }

    // pair with gpg's cert-digest-algo
    netpgp_setvar(netpgp, "hash", "SHA256");

    // subset of gpg's personal-cipher-preferences
    // here only one cipher can be selected
    netpgp_setvar(netpgp, "cipher", "CAST5");

    if (!netpgp_init(netpgp)) {
        status = PEP_INIT_CRYPTO_LIB_INIT_FAILED;
        free(netpgp);
        netpgp=NULL;
        goto unlock_netpgp;
    }

    //pgp_set_debug_level("packet-parse.c");
    //pgp_set_debug_level("openssl_crypto.c");
    //pgp_set_debug_level("crypto.c");

unlock_netpgp:
    pthread_mutex_unlock(&netpgp_mutex);

    return status;
}

static void release_netpgp()
{
    TRACE_FUNCS()
    if(pthread_mutex_lock(&netpgp_mutex)){
        return;
    }
    netpgp_end(netpgp);
    memset(netpgp, 0x0, sizeof(netpgp_t));

    pthread_mutex_destroy(&netpgp_mutex);

    return;
}

PEP_STATUS pgp_init(PEP_SESSION session, bool in_first)
{
    TRACE_FUNCS()
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);
    if(!session) return PEP_ILLEGAL_VALUE;

    if (in_first) {
        if((status = init_netpgp()) != PEP_STATUS_OK)
        return status;
    }

    return PEP_STATUS_OK;
}

void pgp_release(PEP_SESSION session, bool out_last)
{
    TRACE_FUNCS()
    assert(session);
    if(!session) return;

    if (out_last){
        release_netpgp();
    }
}

// return 1 if the file contains ascii-armoured text
static unsigned
_armoured(const char *buf, size_t size, const char *pattern)
{
    TRACE_FUNCS()
    unsigned armoured = 0;
    regex_t r;
    if( regcomp(&r, pattern, REG_EXTENDED|REG_NOSUB) ) printf("_armoured error\n");
    if (regexec(&r, buf, size, 0, NULL) == 0) {
        armoured = 1;
    }
    regfree(&r);
    return armoured;
}

// Iterate through netpgp' reported valid signatures
// fill a list of valid figerprints
// returns PEP_STATUS_OK if all sig reported valid
// error status otherwise.
static PEP_STATUS _validation_results(
        netpgp_t *netpgp,
        pgp_validation_t *vresult,
        stringlist_t **keylist
    )
{
    TRACE_FUNCS()
    time_t    now;
    time_t    t;

    *keylist = NULL;

    now = time(NULL);
    if (now < vresult->birthtime) {
        // signature is not valid yet
        return PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH;
    }
    if (vresult->duration != 0 && now > vresult->birthtime + vresult->duration) {
        // signature has expired
        t = vresult->duration + vresult->birthtime;
        return PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH;
    }
    if (vresult->validc && vresult->valid_sigs &&
        !vresult->invalidc && !vresult->unknownc ) {
        
        stringlist_t *_keylist;

        // caller responsible to free
        _keylist = new_stringlist(NULL);
        assert(_keylist);
        if (_keylist == NULL) {
            return PEP_OUT_OF_MEMORY;
        }
        
        stringlist_t *k = _keylist;
        unsigned c = 0;
        for (unsigned n = 0; n < vresult->validc; ++n) {
            unsigned from = 0;
            const pgp_key_t     *signer;
            char *fprstr = NULL;
            const uint8_t *keyid = vresult->valid_sigs[n].signer_id;

            signer = pgp_getkeybyid(netpgp->io, netpgp->pubring,
                                    keyid, &from, NULL, NULL,
                                    0, 0); /* check neither revocation nor expiry
                                              as is should be checked already */
            if(signer)
                uint_to_string(signer->pubkeyfpr.fingerprint, &fprstr, signer->pubkeyfpr.length);
            else
                continue;

            if (fprstr == NULL){
                free_stringlist(_keylist);
                return PEP_OUT_OF_MEMORY;
            }

            k = stringlist_add(k, fprstr);

            free(fprstr);

            if(!k){
                free_stringlist(_keylist);
                return PEP_OUT_OF_MEMORY;
            }

            c++;
        }
        if(c > 0) {
            *keylist = _keylist;
            return PEP_STATUS_OK;
        }

        free_stringlist(_keylist);
        return PEP_VERIFY_NO_KEY;
    }
    if (vresult->validc + vresult->invalidc + vresult->unknownc == 0) {
        // No signatures found - is this memory signed?
        return PEP_VERIFY_NO_KEY;
    }

    if (vresult->invalidc) {
        // some invalid signatures
        return PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH;
    }

    // only unknown sigs
    return PEP_DECRYPTED;
}

#define ARMOR_HEAD "^-----BEGIN PGP MESSAGE-----"_ENDL
PEP_STATUS pgp_decrypt_and_verify(
    PEP_SESSION session, const char *ctext, size_t csize,
    const char *dsigtext, size_t dsigsize,
    char **ptext, size_t *psize, stringlist_t **keylist,
    char** filename_ptr // will be ignored
    )
{
    TRACE_FUNCS()
    char *_ptext = NULL;
    char* passphrase = NULL;

    PEP_STATUS result;
    stringlist_t *_keylist = NULL;

    assert(session);
    assert(ctext);
    assert(csize);
    assert(ptext);
    assert(psize);
    assert(keylist);

    passphrase = session->curr_passphrase;
    if(passphrase && passphrase[0]) {
        netpgp_set_validation_password(passphrase);
    }

    if(!session || !ctext || !csize || !ptext || !psize || !keylist)
        return PEP_ILLEGAL_VALUE;

    if(pthread_mutex_lock(&netpgp_mutex)){
        return PEP_UNKNOWN_ERROR;
    }

    *ptext = NULL;
    *psize = 0;
    *keylist = NULL;

    pgp_validation_t *vresult = malloc(sizeof(pgp_validation_t));
    memset(vresult, 0x0, sizeof(pgp_validation_t));

    key_id_t *recipients_key_ids = NULL;
    unsigned recipients_count = 0;

    pgp_memory_t *mem = pgp_decrypt_and_validate_buf(
        netpgp,
        vresult,
        ctext, csize,
        netpgp->secring, netpgp->pubring,
        _armoured(ctext, csize, ARMOR_HEAD),
        &recipients_key_ids, &recipients_count
    );

    if (mem == NULL) {
        result = PEP_OUT_OF_MEMORY;
        goto unlock_netpgp;
    }

    const size_t _psize = pgp_mem_len(mem);
    if (_psize){
        if ((_ptext = malloc(_psize + 1)) == NULL) {
            result = PEP_OUT_OF_MEMORY;
            goto free_pgp;
        }
        memcpy(_ptext, pgp_mem_data(mem), _psize);
        _ptext[_psize] = '\0'; // safeguard for naive users
        result = PEP_DECRYPTED;
    }else{
        result = PEP_DECRYPT_NO_KEY;
        goto free_pgp;
    }

    if (result == PEP_DECRYPTED) {
        result = _validation_results(netpgp, vresult, &_keylist);
        printf("result=%x\n",result);
        if (result == PEP_DECRYPTED || result == PEP_VERIFY_NO_KEY) {
            if((_keylist = new_stringlist("")) == NULL) {
                result = PEP_OUT_OF_MEMORY;
                goto free_ptext;
            }
            result = PEP_DECRYPTED;
        }else if (result != PEP_STATUS_OK) {
            goto free_ptext;
        }else{
            result = PEP_DECRYPTED_AND_VERIFIED;
        }
    }

    stringlist_t *k = _keylist;
    for (unsigned n = 0; n < recipients_count; ++n) {
        unsigned from = 0;
        const pgp_key_t     *rcpt;
        char *fprstr = NULL;
        key_id_t *keyid = &recipients_key_ids[n];

        rcpt = pgp_getkeybyid(netpgp->io, netpgp->pubring,
                                *keyid, &from, NULL, NULL,
                                0, 0); /* check neither revocation nor expiry*/
        if(rcpt)
            uint_to_string(rcpt->pubkeyfpr.fingerprint, &fprstr, rcpt->pubkeyfpr.length);
        else
            // if no key found put ID instead of fpr
            uint_to_string(*keyid, &fprstr, sizeof(key_id_t));

        if (fprstr == NULL){
            result = PEP_OUT_OF_MEMORY;
            goto free_keylist;
        }

        k = stringlist_add_unique(k, fprstr);

        free(fprstr);

        if(!k){
            result = PEP_OUT_OF_MEMORY;
            goto free_keylist;
        }
    }

    if (result == PEP_DECRYPTED_AND_VERIFIED || result == PEP_DECRYPTED) {
        *ptext = _ptext;
        *psize = _psize;
        (*ptext)[*psize] = 0; // safeguard for naive users
        *keylist = _keylist;

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

unlock_netpgp:
    free(recipients_key_ids);
    pthread_mutex_unlock(&netpgp_mutex);

    return result;
}

#define ARMOR_SIG_HEAD    "^-----BEGIN PGP (SIGNATURE|SIGNED MESSAGE)-----"_ENDL
PEP_STATUS pgp_verify_text(
    PEP_SESSION session, const char *text, size_t size,
    const char *signature, size_t sig_size, stringlist_t **keylist
    )
{
    TRACE_FUNCS()
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
        return PEP_ILLEGAL_VALUE;

    if(pthread_mutex_lock(&netpgp_mutex)){
        return PEP_UNKNOWN_ERROR;
    }

    *keylist = NULL;

    vresult = malloc(sizeof(pgp_validation_t));
    if (vresult == NULL) {
        result = PEP_OUT_OF_MEMORY;
        goto unlock_netpgp;
    }
    memset(vresult, 0x0, sizeof(pgp_validation_t));

    signedmem = pgp_memory_new();
    if (signedmem == NULL) {
        result = PEP_OUT_OF_MEMORY;
        goto unlock_netpgp;
    }
    pgp_memory_add(signedmem, (const uint8_t*)text, size);

    sig = pgp_memory_new();
    if (sig == NULL) {
        pgp_memory_free(signedmem);
        result = PEP_OUT_OF_MEMORY;
        goto unlock_netpgp;
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

    free_stringlist(_keylist);

free_pgp:
    // free done by pgp_validate_mem_detached
    // pgp_memory_free(sig);
    // pgp_memory_free(signedmem);
    pgp_validate_result_free(vresult);

unlock_netpgp:
    pthread_mutex_unlock(&netpgp_mutex);

    return result;
}

PEP_STATUS pgp_sign_only(
    PEP_SESSION session, const char* fpr, const char *ptext,
    size_t psize, char **stext, size_t *ssize
    )
{
    TRACE_FUNCS()
    pgp_key_t *signer = NULL;
    pgp_seckey_t *seckey = NULL;
    pgp_memory_t *signedmem = NULL;
    pgp_memory_t *text = NULL;
    pgp_output_t *output;
    
    const char *hashalg;
    pgp_keyring_t *snrs;

    pgp_create_sig_t    *sig;
    uint8_t    keyid[PGP_KEY_ID_SIZE];

    PEP_STATUS result;

    assert(session);
    assert(fpr);
    assert(ptext);
    assert(psize);
    assert(stext);
    assert(ssize);

    if(!session || !ptext || !psize || !stext || !ssize || !fpr || !fpr[0])
        return PEP_ILLEGAL_VALUE;

    if(pthread_mutex_lock(&netpgp_mutex)){
        return PEP_UNKNOWN_ERROR;
    }

    *stext = NULL;
    *ssize = 0;

    if ((snrs = calloc(1, sizeof(*snrs))) == NULL) {
        result = PEP_OUT_OF_MEMORY;
        goto unlock_netpgp;
    }
    
    assert(fpr && fpr[0]);

    uint8_t *uint_fpr = NULL;
    size_t fprlen;
    unsigned from = 0;

    if (string_to_uint(fpr, &uint_fpr, &fprlen)) {
        if ((signer = (pgp_key_t *)pgp_getkeybyfpr(netpgp->io, netpgp->secring, uint_fpr, fprlen, &from, NULL, 1,1)) == NULL) {
            /* reject revoked and expired */
            result = PEP_KEY_NOT_FOUND;
printf("%s:%d, Key not found\n",__FILE__,__LINE__);

            goto free_snrs;
        }
    } else{
        result = PEP_ILLEGAL_VALUE;
        goto free_snrs;
    }

    // add key to signers
    pgp_keyring_add(snrs, signer);
    if(snrs->keys == NULL){
        result = PEP_OUT_OF_MEMORY;
        goto free_snrs;
    }

    /* Empty keylist ?*/
    if(snrs->keyc == 0){
        result = PEP_ILLEGAL_VALUE;
        goto free_snrs;
    }

    seckey = pgp_key_get_certkey(signer);

    /* No signing key. Revoked ? */
    if(seckey == NULL){
        result = PEP_GET_KEY_FAILED;
        goto free_snrs;
    }

    hashalg = netpgp_getvar(netpgp, "hash");
    
    const char *_stext;
    size_t _ssize;

    text = pgp_memory_new();
    pgp_memory_add(text, (const uint8_t*)ptext, psize);

    pgp_setup_memory_write(&output, &signedmem, psize);
    pgp_writer_push_armor_msg(output);

    pgp_hash_alg_t hash_alg = pgp_str_to_hash_alg(hashalg);
    
    sig = pgp_create_sig_new();
    pgp_start_sig(sig, seckey, hash_alg, PGP_SIG_BINARY);

    pgp_sig_add_data(sig, pgp_mem_data(text), pgp_mem_len(text));
    pgp_memory_free(text);

    pgp_add_creation_time(sig, time(NULL));
    pgp_add_sig_expiration_time(sig, 0);
    pgp_keyid(keyid, sizeof(keyid), &seckey->pubkey, hash_alg);
    pgp_add_issuer_keyid(sig, keyid);
    pgp_end_hashed_subpkts(sig);

    pgp_write_sig(output, sig, &seckey->pubkey, seckey);
    pgp_writer_close(output);
    pgp_create_sig_delete(sig);
   
    if (!signedmem) {
        result = PEP_UNENCRYPTED;
        goto free_snrs;
    }
    _stext = (char*) pgp_mem_data(signedmem);
    _ssize = pgp_mem_len(signedmem);
        
    // Allocate transferable buffer
    char *_buffer = malloc(_ssize + 1);

    assert(_buffer);
    if (_buffer == NULL) {
        result = PEP_OUT_OF_MEMORY;
        goto free_signedmem;
    }

    memcpy(_buffer, _stext, _ssize);
    *stext = _buffer;
    *ssize = _ssize;
    (*stext)[*ssize] = 0; // safeguard for naive users

    result = PEP_STATUS_OK;

free_signedmem :
    pgp_memory_free(signedmem);
free_snrs :
    pgp_keyring_free(snrs);
unlock_netpgp:
    pthread_mutex_unlock(&netpgp_mutex);

    return result;
}


PEP_STATUS pgp_encrypt_and_sign(
    PEP_SESSION session, const stringlist_t *keylist, const char *ptext,
    size_t psize, char **ctext, size_t *csize
    )
{
    TRACE_FUNCS()
    PEP_STATUS result = PEP_STATUS_OK;
    stringlist_t *klp;
    int ret;
    uint8_t *fpr = NULL;
    unsigned from;
    size_t len = 0;

    pgp_memory_t *mem = NULL;
    pgp_keyring_t *rcpts = NULL;
    pgp_seckey_t *seckey = NULL;
    pgp_key_t *signer = NULL;
    pgp_key_t *key = NULL;

    assert(netpgp->secring);

    string_to_uint(keylist->value, &fpr, &len);

    from = 0;
    signer = pgp_getkeybyfpr(netpgp->io, netpgp->secring, fpr, len, &from, NULL, 0, 0 );
    if(!signer) return PEP_KEY_NOT_FOUND;

    rcpts = malloc(sizeof(pgp_keyring_t));
    memset(rcpts,0,sizeof(pgp_keyring_t));

    klp = keylist; 
    while(klp) {
        string_to_uint(klp->value, &fpr, &len);
        from = 0;
        key = pgp_getkeybyfpr(netpgp->io, netpgp->pubring, fpr, len, &from, NULL, 0, 0 );
        if(key) {
            pgp_keyring_add(rcpts, key);
        }
        klp = klp->next;
    }

    mem = netpgp_encrypt_and_sign(netpgp, rcpts, seckey, ptext, psize, true, 1);

    free(rcpts);

    return result;
}

PEP_STATUS pgp_encrypt_only(
        PEP_SESSION session, const stringlist_t *keylist, const char *ptext,
        size_t psize, char **ctext, size_t *csize
    )
{
    TRACE_FUNCS()
    PEP_STATUS result = PEP_STATUS_OK;
    pgp_memory_t *mem;
    pgp_keyring_t *rcpts = NULL;
    unsigned from;
    size_t len = 0;
    uint8_t *fpr = NULL;
    pgp_key_t *key = NULL;
    stringlist_t *klp;

    rcpts = malloc(sizeof(pgp_keyring_t));
    memset(rcpts,0,sizeof(pgp_keyring_t));

    klp = keylist; 
    while(klp) {
        string_to_uint(klp->value, &fpr, &len);
        from = 0;
        key = pgp_getkeybyfpr(netpgp->io, netpgp->pubring, fpr, len, &from, NULL, 0, 0 );
        if(key) {
            pgp_keyring_add(rcpts, key);
        }
        klp = klp->next;
    }

    mem = netpgp_encrypt_and_sign(netpgp, rcpts, NULL, ptext, psize, false, 1);

    free(rcpts);

    return result;
}


PEP_STATUS pgp_generate_keypair(
    PEP_SESSION session, pEp_identity *identity
    )
{
    TRACE_FUNCS()
    pgp_key_t    newseckey;
    pgp_key_t    *newpubkey;

    PEP_STATUS result;
    char newid[1024];
    const char *hashalg;
    const char *cipher;

    assert(session);
    assert(identity);
    assert(identity->address);
    assert(identity->fpr == NULL);
    assert(identity->username);

    if(!session || !identity ||
       !identity->address || identity->fpr || !identity->username)
        return PEP_ILLEGAL_VALUE;

    if(pthread_mutex_lock(&netpgp_mutex)){
        return PEP_UNKNOWN_ERROR;
    }

    if(snprintf(newid, sizeof(newid),
        "%s <%s>", identity->username, identity->address) >= sizeof(newid)){
        result =  PEP_BUFFER_TOO_SMALL;
        goto unlock_netpgp;
    }

    hashalg = netpgp_getvar(netpgp, "hash");
    cipher = netpgp_getvar(netpgp, "cipher");

    bzero(&newseckey, sizeof(newseckey));

    // Generate the key
    if (!pgp_rsa_generate_keypair(&newseckey, 4096, 65537UL, hashalg, cipher,
                                  (const uint8_t *) "", (const size_t) 0))
    {
        result = PEP_CANNOT_CREATE_KEY;
        goto free_seckey;
    }

    /* make a public key out of generated secret key */
    if((newpubkey = pgp_ensure_pubkey(
            netpgp->pubring,
            &newseckey.key.seckey.pubkey,
            newseckey.pubkeyid))==NULL)
    {
        result = PEP_OUT_OF_MEMORY;
        goto free_seckey;
    }

    // "Expire-Date: 1y\n";
    if (!pgp_add_selfsigned_userid(&newseckey, newpubkey,
                                  (uint8_t *)newid, 365*24*3600))
    {
        result = PEP_CANNOT_CREATE_KEY;
        goto delete_pubkey;
    }

    if (newpubkey == NULL)
    {
        result = PEP_OUT_OF_MEMORY;
        goto delete_pubkey;
    }

    // Append key to netpgp's rings (key ownership transfered)
    if (!pgp_keyring_add(netpgp->secring, &newseckey)){
        result = PEP_OUT_OF_MEMORY;
        goto delete_pubkey;
    }

    // save rings
    if (netpgp_save_pubring(netpgp) && netpgp_save_secring(netpgp))
    {
        char *fprstr = NULL;
        uint_to_string(newseckey.pubkeyfpr.fingerprint, &fprstr, newseckey.pubkeyfpr.length);

        if (fprstr == NULL) {
            result = PEP_OUT_OF_MEMORY;
            goto pop_secring;
        }

        /* keys saved, pass fingerprint back */
        identity->fpr = fprstr;
        result = PEP_STATUS_OK;

        /* free nothing, everything transfered */
        goto unlock_netpgp;
    } else {
        /* XXX in case only pubring save succeed
         * pubring file is left as-is, but backup restore
         * could be attempted if such corner case matters */
        result = PEP_UNKNOWN_ERROR;
    }

pop_secring:
    ((pgp_keyring_t *)netpgp->secring)->keyc--;
delete_pubkey:
    pgp_deletekeybyfpr(netpgp->io,
                    (pgp_keyring_t *)netpgp->pubring,
                    newseckey.pubkeyfpr.fingerprint,
                    newseckey.pubkeyfpr.length);
free_seckey:
    pgp_key_free(&newseckey);
unlock_netpgp:
    pthread_mutex_unlock(&netpgp_mutex);

    return result;
}

PEP_STATUS pgp_delete_keypair(PEP_SESSION session, const char *fprstr)
{
    TRACE_FUNCS()
    uint8_t *fpr;
    size_t length;

    PEP_STATUS result;

    assert(session);
    assert(fprstr);

    if (!session || !fprstr)
        return PEP_ILLEGAL_VALUE;

    if(pthread_mutex_lock(&netpgp_mutex)){
        return PEP_UNKNOWN_ERROR;
    }

    if (string_to_uint(fprstr, &fpr, &length)) {
        unsigned insec = pgp_deletekeybyfpr(netpgp->io,
                                (pgp_keyring_t *)netpgp->secring,
                                (const uint8_t *)fpr, length);
        unsigned inpub = pgp_deletekeybyfpr(netpgp->io,
                                (pgp_keyring_t *)netpgp->pubring,
                                (const uint8_t *)fpr, length);
        if(!insec && !inpub){
            result = PEP_KEY_NOT_FOUND;
printf("%s:%d, Key not found\n",__FILE__,__LINE__);

            goto unlock_netpgp;
        } else {
            result = PEP_STATUS_OK;
        }
    }else{
        result = PEP_OUT_OF_MEMORY;
        goto unlock_netpgp;
    }

    // save rings
    if (netpgp_save_pubring(netpgp) &&
        netpgp_save_secring(netpgp))
    {
        result = PEP_STATUS_OK;
    }else{
        result = PEP_UNKNOWN_ERROR;
    }

unlock_netpgp:
    pthread_mutex_unlock(&netpgp_mutex);

    return result;
}

void stringlist_from_keyring(pgp_keyring_t* keyring, stringlist_t **list)
{
    TRACE_FUNCS()

    int i;
    char *fpr;
    pgp_key_t key;

    for(i = 0; i < keyring->keyc; i++) {
        key = keyring->keys[i];
        if(uint_to_string(key.pubkeyfpr.fingerprint, &fpr, PGP_FINGERPRINT_SIZE)) {
            if(!*list) *list = new_stringlist(fpr);
            else stringlist_add(*list, fpr);
        }
    }
}

pEp_identity *ident_from_uid_fpr(char *uid, uint8_t *fpr)
{
    char *address;
    char *user_id;
    char *username;

    pEp_identity *ident;
    ident = malloc(sizeof(pEp_identity));

    ident->fpr = NULL;
    uint_to_string(fpr, &ident->fpr, PGP_FINGERPRINT_SIZE);
    printf("FPR: %s\n",ident->fpr);

    username=strtok(uid, "<");
    if(username[strlen(username)-1]==' ') username[strlen(username)-1]=0;
    ident->username=malloc(strlen(username));
    strcpy(ident->username,username);
    printf("User name: %s\n",ident->username);

    address=strtok(NULL, ">");
    ident->address=malloc(strlen(address));
    strcpy(ident->address,address);
    printf("Address: %s\n",ident->address);

    user_id=strtok(address, "@");
    ident->user_id=malloc(strlen(user_id));
    strcpy(ident->user_id,user_id);
    printf("User ID: %s\n",ident->address);

    return ident;
}

identity_list *add_idents_from_keyring(pgp_keyring_t* keyring, identity_list *list)
{
    TRACE_FUNCS()
    int i, j;
    pgp_key_t key;
    char *uid;
    pEp_identity *ident;

    for(i = 0; i < keyring->keyc; i++ ) {
        key = keyring->keys[i];
        for(j = 0; j < key.uidc; j++) {
            uid = strdup(key.uids[j]);
            ident = ident_from_uid_fpr(uid, key.pubkeyfpr.fingerprint);
            list = identity_list_add(list, ident);
         }
    }

    return list;
}

#define ARMOR_KEY_HEAD "^-----BEGIN PGP (PUBLIC|PRIVATE) KEY BLOCK-----"_ENDL
PEP_STATUS pgp_import_keydata(PEP_SESSION session, const char *key_data,
                              size_t size, identity_list **private_idents,
                              stringlist_t** imported_keys,
                              uint64_t* changed_key_index)
{
    TRACE_FUNCS()

    int ret;
    PEP_STATUS result = PEP_STATUS_OK;
    char* passphrase = NULL;

    if (!imported_keys && changed_key_index)
        return PEP_ILLEGAL_VALUE;

    stringlist_t* key_fprs = NULL;
    pgp_memory_t *mem = NULL;
 
    assert(session);
    assert(key_data);

    passphrase = session->curr_passphrase;
    if(passphrase && passphrase[0]) {
        netpgp_set_validation_password(passphrase);
    }

    //pgp_set_debug_level("validate.c");
    //pgp_set_debug_level("reader.c");

    if(!session || !key_data)
        return PEP_ILLEGAL_VALUE;

    if(pthread_mutex_lock(&netpgp_mutex)){
        return PEP_UNKNOWN_ERROR;
    }

    mem = pgp_memory_new();
    if (mem == NULL) {
        result = PEP_OUT_OF_MEMORY;
        goto unlock_netpgp;
    }

    pgp_memory_add(mem, (const uint8_t*)key_data, size);
    ret = pgp_keyring_read_from_mem(netpgp, netpgp->pubring, netpgp->secring, _armoured(key_data, size, ARMOR_KEY_HEAD), mem, 1);
    switch(ret) {
        case PGP_PASSWORD_REQUIRED:
            printf("Password required\n");
            result=PEP_PASSPHRASE_REQUIRED;
            goto unlock_netpgp;
            break;
        case PGP_WRONG_PASSWORD:
            printf("Wrong password\n");
            result=PEP_WRONG_PASSPHRASE;
            goto unlock_netpgp;
            break;
        default:
            result=PEP_KEY_IMPORTED;
            if(changed_key_index) {
                (*changed_key_index)=0;
                if (netpgp->pubring->keyc) {
                    (*changed_key_index)=pow(2,netpgp->pubring->keyc)-1;
                }
                //(*changed_key_index)=pow(2,netpgp->secring->keyc+netpgp->pubring->keyc)-1;
            }
            break;
    }
    pgp_memory_free(mem);

    if(private_idents) {
        printf("Return private indents\n");
        (*private_idents) = NULL;
        (*private_idents) = add_idents_from_keyring(netpgp->secring, (*private_idents));
        //(*private_idents) = add_idents_from_keyring(netpgp->pubring, (*private_idents));
    }

    if(imported_keys) {
        printf("Return list of imported keys\n");
        stringlist_from_keyring(netpgp->pubring, imported_keys);
    }

    netpgp_save_pubring(netpgp);
    netpgp_save_secring(netpgp);

    // save rings
    //if ( !netpgp_save_pubring(netpgp) || !netpgp_save_secring(netpgp) )
    //{
    //    result = PEP_UNKNOWN_ERROR;
    //}

unlock_netpgp:
    pthread_mutex_unlock(&netpgp_mutex);

    return result;
}

static PEP_STATUS _export_keydata(
    pgp_key_t *key,
    char **buffer,
    size_t *buflen
    )
{
    TRACE_FUNCS()
    PEP_STATUS result;
    pgp_output_t *output;
    pgp_memory_t *mem;
    pgp_setup_memory_write(&output, &mem, 128);

    if (mem == NULL || output == NULL) {
        return PEP_ILLEGAL_VALUE;
    }

    if (!pgp_write_xfer_key(output, key, 1)) {
        result = PEP_UNKNOWN_ERROR;
        goto free_mem;
    }

    *buffer = NULL;
    *buflen = pgp_mem_len(mem);

    // Allocate transferable buffer
    *buffer = malloc(*buflen + 1);
    assert(*buffer);
    if (*buffer == NULL) {
        result = PEP_OUT_OF_MEMORY;
        goto free_mem;
    }

    memcpy(*buffer, pgp_mem_data(mem), *buflen);
    (*buffer)[*buflen] = 0; // safeguard for naive users

    return PEP_STATUS_OK;

free_mem :
    pgp_teardown_memory_write(output, mem);

    return result;
}

PEP_STATUS pgp_export_keydata(
    PEP_SESSION session, const char *fprstr, char **key_data, size_t *size,
    bool secret
    )
{
    TRACE_FUNCS()
    pgp_key_t *key;
    uint8_t *fpr = NULL;
    size_t fprlen;

    PEP_STATUS result;
    char *buffer;
    size_t buflen;
    const pgp_keyring_t *srcring;

    assert(session);
    assert(fprstr);
    assert(key_data);
    assert(size);

    if (secret)
        srcring = netpgp->secring;
    else
        srcring = netpgp->pubring;
    
    if (!session || !fprstr || !key_data || !size)
        return PEP_ILLEGAL_VALUE;

    if(pthread_mutex_lock(&netpgp_mutex)) {
        return PEP_UNKNOWN_ERROR;
    }

    if (string_to_uint(fprstr, &fpr, &fprlen)) {
        unsigned from = 0;
        if ((key = (pgp_key_t *)pgp_getkeybyfpr(netpgp->io, srcring, fpr, fprlen, &from, NULL,0,0)) == NULL) {
            result = PEP_KEY_NOT_FOUND;
printf("%s:%d, Key not found\n",__FILE__,__LINE__);

            goto unlock_netpgp;
        }
    }else{
        result = PEP_OUT_OF_MEMORY;
        goto unlock_netpgp;
    }

    result = _export_keydata(key, &buffer, &buflen);

    if(result == PEP_STATUS_OK)
    {
        *key_data = buffer;
        *size = buflen;
        result = PEP_STATUS_OK;
    }

unlock_netpgp:
    pthread_mutex_unlock(&netpgp_mutex);

    return result;
}

struct HKP_answer {
  char *memory;
  size_t size;
};

PEP_STATUS pgp_recv_key(PEP_SESSION session, const char *pattern)
{
    TRACE_FUNCS()
    assert(!"pgp_recv_key not implemented");
    return PEP_UNKNOWN_ERROR;
}

typedef PEP_STATUS (*find_key_cb_t)(void*, pgp_key_t *);

static PEP_STATUS find_keys_do(pgp_keyring_t* keyring,
        const char *pattern, find_key_cb_t cb, void* cb_arg)
{
    TRACE_FUNCS()
    uint8_t *fpr = NULL;
    size_t length;
    unsigned from;
    pgp_key_t *key;

    PEP_STATUS result;

    // Try find a fingerprint in pattern
    if (string_to_uint(pattern, &fpr, &length)) {
        // Only one fingerprint can match
        from = 0;
        key = pgp_getkeybyfpr(netpgp->io, keyring, fpr, length, &from, NULL, 0, 0);
        if ( key == NULL) {
            return PEP_KEY_NOT_FOUND;
        }
        result = cb(cb_arg, key);
    } else {
        TRACE_FUNCS()
        // Search by name for pattern. Can match many.
        from = 0;
        result = PEP_KEY_NOT_FOUND;
printf("%s:%d, Key not found\n",__FILE__,__LINE__);
        while((key = (pgp_key_t *)pgp_getnextkeybyname(netpgp->io, keyring, (const char *)pattern, &from)) != NULL) {
            result = cb(cb_arg, key);
            if (result != PEP_STATUS_OK)
                break;
            from++;
        }
    }

    return result;
}

static PEP_STATUS add_key_uint_to_stringinglist(void *arg, pgp_key_t *key)
{
    TRACE_FUNCS()
    stringlist_t **keylist = arg;
    char *newfprstr = NULL;

    uint_to_string(key->pubkeyfpr.fingerprint, &newfprstr, key->pubkeyfpr.length);

    if (newfprstr == NULL) {
        return PEP_OUT_OF_MEMORY;
    } else {

        stringlist_add(*keylist, newfprstr);
        free(newfprstr);
        if (*keylist == NULL) {
            return PEP_OUT_OF_MEMORY;
        }
    }
    return PEP_STATUS_OK;
}

static PEP_STATUS add_secret_key_uint_to_stringinglist(void *arg, pgp_key_t *key)
{
    TRACE_FUNCS()
    if (pgp_is_key_secret(key)) {
        stringlist_t **keylist = arg;
        char *newfprstr = NULL;
        uint_to_string(key->pubkeyfpr.fingerprint, &newfprstr, key->pubkeyfpr.length);
        if (newfprstr == NULL) {
            return PEP_OUT_OF_MEMORY;
        } else {
            stringlist_add(*keylist, newfprstr);
            free(newfprstr);
            if (*keylist == NULL) {
                return PEP_OUT_OF_MEMORY;
            }
        }
    }
    return PEP_STATUS_OK;
}

static PEP_STATUS add_keyinfo_to_stringpair_list(void* arg, pgp_key_t *key) {
    TRACE_FUNCS()
    stringpair_list_t** keyinfo_list = (stringpair_list_t**)arg;
    stringpair_t* pair = NULL;
    char* id_fpr = NULL;
    char* primary_userid = (char*)pgp_key_get_primary_userid(key);

// Unused:
//    bool key_revoked = false;

//    PEP_STATUS key_status = pgp_key_revoked(session, id_fpr, &key_revoked);

//    if (key_revoked || key_status == PEP_GET_KEY_FAILED)
//        return PEP_STATUS_OK; // we just move on

    uint_to_string(key->pubkeyfpr.fingerprint, &id_fpr, key->pubkeyfpr.length);

    pair = new_stringpair(id_fpr, primary_userid);

    if (pair == NULL)
        return PEP_OUT_OF_MEMORY;

    *keyinfo_list = stringpair_list_add(*keyinfo_list, pair);
    free(id_fpr);
    if (*keyinfo_list == NULL)
        return PEP_OUT_OF_MEMORY;
    return PEP_STATUS_OK;
}

PEP_STATUS pgp_find_keys(
    PEP_SESSION session, const char *pattern, stringlist_t **keylist
    )
{
    TRACE_FUNCS()
    stringlist_t *_keylist, *_k;

    PEP_STATUS result;

    assert(session);
    assert(pattern);
    assert(keylist);

    if (!session || !pattern || !keylist )
    {
        return PEP_ILLEGAL_VALUE;
    }

    if (pthread_mutex_lock(&netpgp_mutex))
    {
        return PEP_UNKNOWN_ERROR;
    }

    *keylist = NULL;
    _keylist = new_stringlist(NULL);
    if (_keylist == NULL) {
        result = PEP_OUT_OF_MEMORY;
        goto unlock_netpgp;
    }
    _k = _keylist;

    result = find_keys_do(netpgp->pubring, pattern, &add_key_uint_to_stringinglist, &_k);

    if (result == PEP_STATUS_OK) {
        *keylist = _keylist;
        // Transfer ownership, no free
        goto unlock_netpgp;
    }

    free_stringlist(_keylist);

unlock_netpgp:
    pthread_mutex_unlock(&netpgp_mutex);

    return result;
}

#define HKP_REQ_PREFIX "keytext="
#define HKP_REQ_PREFIX_LEN 8

PEP_STATUS pgp_send_key(PEP_SESSION session, const char *pattern)
{
    TRACE_FUNCS()
    assert(!"pgp_send_key not implemented");
    return PEP_UNKNOWN_ERROR;
}


PEP_STATUS pgp_get_key_rating(
    PEP_SESSION session, const char *fprstr, PEP_comm_type *comm_type)
{
    TRACE_FUNCS()
    pgp_key_t *key;
    uint8_t *fpr = NULL;
    unsigned from = 0;
    size_t length;
    int rating;

    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);
    assert(fprstr);
    assert(comm_type);

    if (!session || !fprstr || !comm_type )
        return PEP_ILLEGAL_VALUE;

    *comm_type = PEP_ct_unknown;

    if(pthread_mutex_lock(&netpgp_mutex)){
        return PEP_UNKNOWN_ERROR;
    }

    if (!string_to_uint(fprstr, &fpr, &length)) {
        status = PEP_ILLEGAL_VALUE;
        goto unlock_netpgp;
    }

    key = pgp_getkeybyfpr(netpgp->io, netpgp->pubring, fpr, length, &from, NULL, 0, 0);
    if(key == NULL)
    {
        status = PEP_KEY_NOT_FOUND;
        goto unlock_netpgp;
    }
    rating = pgp_key_get_rating(key);
    switch(rating){
    case PGP_VALID:
        *comm_type = PEP_ct_OpenPGP_unconfirmed;
        break;
    case PGP_WEAK:
        *comm_type = PEP_ct_OpenPGP_weak_unconfirmed;
        break;
    case PGP_TOOSHORT:
        *comm_type = PEP_ct_key_too_short;
        break;
    case PGP_INVALID:
        *comm_type = PEP_ct_key_b0rken;
        break;
    case PGP_EXPIRED:
        *comm_type = PEP_ct_key_expired;
        break;
    case PGP_REVOKED:
        *comm_type = PEP_ct_key_revoked;
        break;
    default:
        break;
    }

unlock_netpgp:
    pthread_mutex_unlock(&netpgp_mutex);

    return status;
}

PEP_STATUS pgp_renew_key(
        PEP_SESSION session,
        const char *fprstr,
        const timestamp *ts
    )
{
    TRACE_FUNCS()
    pgp_key_t *pkey;
    pgp_key_t *skey;
    uint8_t fpr[PGP_FINGERPRINT_SIZE];
    size_t length;
    unsigned from = 0;
    time_t duration;
    const uint8_t *primid;

    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);
    assert(fprstr);

    if (!session || !fprstr )
        return PEP_ILLEGAL_VALUE;

    if(ts)
    {
        time_t    now, when;
        now = time(NULL);
        when = mktime((struct tm*)ts);
        if(now && when && when > now){
            duration = when - now;
        }else{
            return PEP_ILLEGAL_VALUE;
        }
    }else{
        /* Default 1 year from now */
        duration = 365*24*3600;
    }

    if(pthread_mutex_lock(&netpgp_mutex)){
        return PEP_UNKNOWN_ERROR;
    }


    if (!string_to_uint(fprstr, &fpr, &length)) {
        status = PEP_ILLEGAL_VALUE;
        goto unlock_netpgp;
    }

    pkey = pgp_getkeybyfpr(netpgp->io, netpgp->pubring, fpr, length, &from, NULL, 1, 0); /* reject revoked, accept expired */

    if(pkey == NULL)
    {
        status = PEP_KEY_NOT_FOUND;
printf("%s:%d, Key not found\n",__FILE__,__LINE__);

        goto unlock_netpgp;
    }

    from = 0;
    skey = pgp_getkeybyfpr( netpgp->io, netpgp->secring, fpr, length, &from, NULL, 1, 0); /* reject revoked, accept expired */

    if(skey == NULL)
    {
        status = PEP_KEY_NOT_FOUND;
printf("%s:%d, Key not found\n",__FILE__,__LINE__);

        goto unlock_netpgp;
    }

    if((primid = pgp_key_get_primary_userid(skey)) == NULL)
    {
        status = PEP_KEY_HAS_AMBIG_NAME;
        goto unlock_netpgp;
    }

    // FIXME : renew in a more gentle way
    if (!pgp_add_selfsigned_userid(skey, pkey, primid, duration))
    {
        status = PEP_CANNOT_CREATE_KEY;
        goto unlock_netpgp;
    }

    // save rings
    if (netpgp_save_pubring(netpgp) &&
        netpgp_save_secring(netpgp))
    {
        status = PEP_STATUS_OK;
    }else{
        status = PEP_UNKNOWN_ERROR;
    }

unlock_netpgp:
    pthread_mutex_unlock(&netpgp_mutex);

    return status;
}

PEP_STATUS pgp_revoke_key(
        PEP_SESSION session,
        const char *fprstr,
        const char *reason
    )
{
    TRACE_FUNCS()
    uint8_t *fpr = NULL;
    size_t length;
    unsigned from = 0;

    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);
    assert(fprstr);

    if (!session || !fprstr)
        return PEP_UNKNOWN_ERROR;

    if(pthread_mutex_lock(&netpgp_mutex)){
        return PEP_UNKNOWN_ERROR;
    }

    // FIXME : deduplicate that code w/ renew
    if (!string_to_uint(fprstr, &fpr, &length)) {
        status = PEP_ILLEGAL_VALUE;
        goto unlock_netpgp;
    }

    pgp_key_t *pkey = pgp_getkeybyfpr( netpgp->io, netpgp->pubring, fpr, length, &from, NULL, 1, 0); /* reject revoked, accept expired */

    if(pkey == NULL)
    {
        status = PEP_KEY_NOT_FOUND;
printf("%s:%d, Key not found\n",__FILE__,__LINE__);

        goto unlock_netpgp;
    }

    from = 0;
    pgp_key_t *skey = pgp_getkeybyfpr( netpgp->io, netpgp->secring, fpr, length, &from, NULL, 1, 0); /* reject revoked, accept expired */

    if(skey == NULL)
    {
        status = PEP_KEY_NOT_FOUND;
printf("%s:%d, Key not found\n",__FILE__,__LINE__);

        goto unlock_netpgp;
    }

    pgp_key_revoke(skey, pkey,
                   0, /* no reason code specified */
                   reason);

unlock_netpgp:
    pthread_mutex_unlock(&netpgp_mutex);

    return status;
}

PEP_STATUS pgp_key_expired(
        PEP_SESSION session,
        const char *fprstr,
        const time_t when,
        bool *expired
    )
{
    TRACE_FUNCS()
    PEP_STATUS status = PEP_STATUS_OK;
    PEP_comm_type comm_type;

    assert(session);
    assert(fprstr);
    assert(expired);

    if (!session || !fprstr || !expired)
        return PEP_UNKNOWN_ERROR;

    // TODO : take "when" in account

    *expired = false;

    status = pgp_get_key_rating(session, fprstr, &comm_type);

    if (status != PEP_STATUS_OK)
        return status;

    if (comm_type == PEP_ct_key_expired){
        *expired = true;
    }

    return PEP_STATUS_OK;
}

PEP_STATUS pgp_key_revoked(
        PEP_SESSION session,
        const char *fprstr,
        bool *revoked
    )
{
    TRACE_FUNCS()
    PEP_STATUS status = PEP_STATUS_OK;
    PEP_comm_type comm_type;

    assert(session);
    assert(fprstr);
    assert(revoked);

    *revoked = false;

    status = pgp_get_key_rating(session, fprstr, &comm_type);

    if (status != PEP_STATUS_OK)
        return status;

    if (comm_type == PEP_ct_key_revoked){
        *revoked = true;
    }

    return PEP_STATUS_OK;
}

PEP_STATUS pgp_key_created(
        PEP_SESSION session,
        const char *fprstr,
        time_t *created
    )
{
    TRACE_FUNCS()
    uint8_t *fpr;
    pgp_key_t *key;
    size_t length;
    unsigned from = 0;

    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);
    assert(fprstr);
    assert(created);

    if (!session || !fprstr || !created)
        return PEP_UNKNOWN_ERROR;

    *created = 0;

    if(pthread_mutex_lock(&netpgp_mutex)){
        return PEP_UNKNOWN_ERROR;
    }

    if (!string_to_uint(fprstr, &fpr, &length)) {
        status = PEP_ILLEGAL_VALUE;
        goto unlock_netpgp;
    }

    key = pgp_getkeybyfpr( netpgp->io, netpgp->pubring, fpr, length, &from, NULL,0,0);

    if (key)
    {
        *created = (time_t) key->key.pubkey.birthtime;
    }
    else
    {
        status = PEP_KEY_NOT_FOUND;
printf("%s:%d, Key not found\n",__FILE__,__LINE__);

        goto unlock_netpgp;
    }



unlock_netpgp:
    pthread_mutex_unlock(&netpgp_mutex);

    return status;
}


PEP_STATUS pgp_list_keyinfo(
        PEP_SESSION session, const char* pattern, stringpair_list_t** keyinfo_list)
{
    TRACE_FUNCS()

    if (!session || !keyinfo_list)
        return PEP_UNKNOWN_ERROR;

    if (pthread_mutex_lock(&netpgp_mutex))
    {
        return PEP_UNKNOWN_ERROR;
    }

// Unused:
//    pgp_key_t *key;

    PEP_STATUS result;

    result = find_keys_do(netpgp->pubring, pattern, &add_keyinfo_to_stringpair_list, (void*)keyinfo_list);

    if (!keyinfo_list)
        result = PEP_KEY_NOT_FOUND;
printf("%s:%d, Key not found\n",__FILE__,__LINE__);


    pthread_mutex_unlock(&netpgp_mutex);

    return result;
}

PEP_STATUS pgp_find_private_keys(
    PEP_SESSION session, const char *pattern, stringlist_t **keylist
)
{
    TRACE_FUNCS()
    stringlist_t *_keylist, *_k;

    PEP_STATUS result;

    assert(session);
    assert(keylist);

    //if (!session || !keylist )
    //{
    //    return PEP_ILLEGAL_VALUE;
    //}

    if (pthread_mutex_lock(&netpgp_mutex))
    {
        return PEP_UNKNOWN_ERROR;
    }

    *keylist = NULL;
    _keylist = new_stringlist(NULL);
    if (_keylist == NULL) {
        result = PEP_OUT_OF_MEMORY;
        goto unlock_netpgp;
    }
    _k = _keylist;

    result = find_keys_do(netpgp->secring, pattern, &add_secret_key_uint_to_stringinglist, &_k);

    if (result == PEP_STATUS_OK) {
        *keylist = _keylist;
        // Transfer ownership, no free
        goto unlock_netpgp;
    }

    free_stringlist(_keylist);

unlock_netpgp:
    pthread_mutex_unlock(&netpgp_mutex);

    return result;
}

PEP_STATUS pgp_contains_priv_key(
        PEP_SESSION session, 
        const char *fpr,
        bool *has_private)
{
    TRACE_FUNCS()
    stringlist_t* keylist = NULL;
    PEP_STATUS status = pgp_find_private_keys(session, fpr, &keylist);
    if (status == PEP_STATUS_OK && keylist) {
        free_stringlist(keylist);
        *has_private = true;
    }
    else {
        *has_private = false;
    }
    return status;
}

PEP_STATUS pgp_import_ultimately_trusted_keypairs(PEP_SESSION session) {
    // Not implemented - netpgp doesn't appear to keep track of trust status in
    // a meaningful way, though there is space for it in the structs.
    TRACE_FUNCS()
    return PEP_STATUS_OK;
}

PEP_STATUS pgp_config_cipher_suite(PEP_SESSION session, PEP_CIPHER_SUITE suite) {
    TRACE_FUNCS()
    if (suite == PEP_CIPHER_SUITE_DEFAULT) {
        return PEP_STATUS_OK;
    } else {
        return PEP_CANNOT_CONFIG;
    }
}
