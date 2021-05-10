// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "pEp_internal.h"
#include "pgp_netpgp.h"

#include <limits.h>

#include "wrappers.h"

#include "netpgp.h"
#include <netpgp/config.h>
#include <netpgp/memory.h>
#include <netpgp/crypto.h>
#include <netpgp/netpgpsdk.h>
#include <netpgp/validate.h>
#include <netpgp/readerwriter.h>

#include <curl/curl.h>
#include <pthread.h>
#include <regex.h>

static netpgp_t netpgp;
static pthread_mutex_t netpgp_mutex;

static PEP_STATUS init_netpgp()
{
    PEP_STATUS status = PEP_STATUS_OK;
    const char *home = NULL;

    if(pthread_mutex_init(&netpgp_mutex, NULL)){
        return PEP_OUT_OF_MEMORY;
    }

    if(pthread_mutex_lock(&netpgp_mutex)){
        return PEP_UNKNOWN_ERROR;
    }

    if (strcmp(setlocale(LC_ALL, NULL), "C") == 0)
        setlocale(LC_ALL, "");

    memset(&netpgp, 0x0, sizeof(netpgp_t));

    // netpgp_setvar(&netpgp, "max mem alloc", "4194304");
    netpgp_setvar(&netpgp, "need seckey", "1");
    // netpgp_setvar(&netpgp, "need userid", "1");

    if (!home)
        home = getenv("HOME");

    if (!home)
        status = PEP_INIT_CRYPTO_LIB_INIT_FAILED;
    
    if(home){
        netpgp_set_homedir(&netpgp,(char*)home, NULL, 0);
    }else{
        status = PEP_INIT_NO_CRYPTO_HOME;
        goto unlock_netpgp;
    }

    // pair with gpg's cert-digest-algo
    netpgp_setvar(&netpgp, "hash", "SHA256");

    // subset of gpg's personal-cipher-preferences
    // here only one cipher can be selected
    netpgp_setvar(&netpgp, "cipher", "CAST5");

    if (!netpgp_init(&netpgp)) {
        status = PEP_INIT_CRYPTO_LIB_INIT_FAILED;
        goto unlock_netpgp;
    }

    // netpgp_set_debug("packet-parse.c");

unlock_netpgp:
    pthread_mutex_unlock(&netpgp_mutex);

    return status;
}

static void release_netpgp()
{
    if(pthread_mutex_lock(&netpgp_mutex)){
        return;
    }
    netpgp_end(&netpgp);
    memset(&netpgp, 0x0, sizeof(netpgp_t));

    pthread_mutex_destroy(&netpgp_mutex);

    return;
}

static PEP_STATUS init_curl(
    pthread_mutex_t *curl_mutex,
    bool in_first)
{
    PEP_STATUS status = PEP_STATUS_OK;

    if(pthread_mutex_init(curl_mutex, NULL)){
        return PEP_OUT_OF_MEMORY;
    }

    if(pthread_mutex_lock(curl_mutex)){
        return PEP_UNKNOWN_ERROR;
    }

    if(in_first){
        curl_global_init(CURL_GLOBAL_DEFAULT);
    }

    pthread_mutex_unlock(curl_mutex);
    return status;
}

static void release_curl(
    pthread_mutex_t *curl_mutex,
    bool out_last)
{
    if(pthread_mutex_lock(curl_mutex)){
        return;
    }

    if(out_last){
        curl_global_cleanup();
    }

    pthread_mutex_destroy(curl_mutex);

    return;
}

static PEP_STATUS curl_get_ctx(
    CURL **curl)
{
    PEP_STATUS status = PEP_STATUS_OK;
    struct curl_slist *headers=NULL;

    if ((*curl = curl_easy_init()) == NULL) {
        return PEP_OUT_OF_MEMORY;
    }

    curl_easy_setopt(*curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(*curl, CURLOPT_MAXREDIRS, 3L);

    headers=curl_slist_append(headers,"Pragma: no-cache");
    if(headers)
        headers=curl_slist_append(headers,"Cache-Control: no-cache");

    if(!headers)
    {
        return PEP_OUT_OF_MEMORY;
    }

    curl_easy_setopt(curl,CURLOPT_HTTPHEADER,headers);
    curl_slist_free_all(headers);

    // TODO curl_easy_setopt(curl,CURLOPT_PROXY,proxy);
    return status;
}

static void curl_release_ctx(
    CURL **curl)
{
    if(*curl)
        curl_easy_cleanup(*curl);

    *curl = NULL;

    return;
}

PEP_STATUS pgp_init(PEP_SESSION session, bool in_first)
{
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
    unsigned armoured = 0;
    regex_t r;
    regcomp(&r, pattern, REG_EXTENDED|REG_NOSUB);
    if (regnexec(&r, buf, size, 0, NULL, 0) == 0) {
        armoured = 1;
    }
    regfree(&r);
    return armoured;
}

/* write key fingerprint hexdump as a string */
static unsigned
fpr_to_str (char **str, const uint8_t *fpr, size_t length)
{
    unsigned i;
    int	n;

    /* 4 hexes per short + null */
    *str = malloc((length / 2) * 4 + 1);

    if(*str == NULL)
        return 0;

    for (n = 0, i = 0 ; i < length; i += 2) {
        n += snprintf(&((*str)[n]), 5, "%02X%02X", fpr[i], fpr[i+1]);
    }

    return 1;
}

/* write key fingerprint bytes read from hex string
 * accept spaces and hexes */
static unsigned
str_to_fpr (const char *str, uint8_t *fpr, size_t *length)
{
    unsigned i,j;

    *length = 0;
    
    if (str == NULL)
        return 0;

    while(*str && *length < PGP_FINGERPRINT_SIZE){
        while (*str == ' ') str++;
        for (j = 0; j < 2; j++) {
            uint8_t *byte = &fpr[*length];
            *byte = 0;
            for (i = 0; i < 2; i++) {
                if (i > 0)
                    *byte = *byte << 4;
                if (*str >= 'a' && *str <= 'f')
                    *byte += 10 + *str - 'a';
                else if (*str >= 'A' && *str <= 'F')
                    *byte += 10 + *str - 'A';
                else if (*str >= '0' && *str <= '9')
                    *byte += *str - '0';
                else
                    return 0;
                str++;
            }
            (*length)++;
        }
    }
    return 1;
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
            const pgp_key_t	 *signer;
            char *fprstr = NULL;
            const uint8_t *keyid = vresult->valid_sigs[n].signer_id;

            signer = pgp_getkeybyid(netpgp->io, netpgp->pubring,
                                    keyid, &from, NULL, NULL,
                                    0, 0); /* check neither revocation nor expiry
                                              as is should be checked already */
            if(signer)
                fpr_to_str(&fprstr,
                           signer->pubkeyfpr.fingerprint,
                           signer->pubkeyfpr.length);
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

#define _ENDL    "\\s*(\r\n|\r|\n)"
#define ARMOR_HEAD    "^-----BEGIN PGP MESSAGE-----"_ENDL
PEP_STATUS pgp_decrypt_and_verify(
    PEP_SESSION session, const char *ctext, size_t csize,
    const char *dsigtext, size_t dsigsize,
    char **ptext, size_t *psize, stringlist_t **keylist,
    char** filename_ptr // will be ignored
    )
{
    char *_ptext = NULL;

    PEP_STATUS result;
    stringlist_t *_keylist = NULL;

    assert(session);
    assert(ctext);
    assert(csize);
    assert(ptext);
    assert(psize);
    assert(keylist);

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

    pgp_memory_t *mem = pgp_decrypt_and_validate_buf(netpgp.io, vresult, ctext, csize,
                netpgp.secring, netpgp.pubring,
                _armoured(ctext, csize, ARMOR_HEAD),
                 &recipients_key_ids, &recipients_count);

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
        result = _validation_results(&netpgp, vresult, &_keylist);
        if (result == PEP_DECRYPTED ||
            result == PEP_VERIFY_NO_KEY) {
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
        const pgp_key_t	 *rcpt;
        char *fprstr = NULL;
        key_id_t *keyid = &recipients_key_ids[n];

        rcpt = pgp_getkeybyid(netpgp.io, netpgp.pubring,
                                *keyid, &from, NULL, NULL,
                                0, 0); /* check neither revocation nor expiry*/
        if(rcpt)
            fpr_to_str(&fprstr,
                       rcpt->pubkeyfpr.fingerprint,
                       rcpt->pubkeyfpr.length);
        else
            // if no key found put ID instead of fpr
            fpr_to_str(&fprstr,
                       *keyid,
                       sizeof(key_id_t));

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

    if (result == PEP_DECRYPTED_AND_VERIFIED
        || result == PEP_DECRYPTED) {
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

    pgp_validate_mem_detached(netpgp.io, vresult, sig,
                NULL,/* output */
                _armoured(signature, sig_size, ARMOR_SIG_HEAD),
                netpgp.pubring,
                signedmem);

    result = _validation_results(&netpgp, vresult, &_keylist);
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

static PEP_STATUS _encrypt_and_sign(
    PEP_SESSION session, const stringlist_t *keylist, const char *ptext,
    size_t psize, char **ctext, size_t *csize, bool do_sign
    )
{
    pgp_key_t *signer = NULL;
    pgp_seckey_t *seckey = NULL;
    pgp_memory_t *signedmem = NULL;
    pgp_memory_t *cmem;
    const char *hashalg;
    pgp_keyring_t *rcpts;

    PEP_STATUS result;
    const stringlist_t *_keylist;

    assert(session);
    assert(keylist);
    assert(ptext);
    assert(psize);
    assert(ctext);
    assert(csize);

    if(!session || !ptext || !psize || !ctext || !csize || !keylist)
        return PEP_ILLEGAL_VALUE;

    if(pthread_mutex_lock(&netpgp_mutex)){
        return PEP_UNKNOWN_ERROR;
    }

    *ctext = NULL;
    *csize = 0;

    if ((rcpts = calloc(1, sizeof(*rcpts))) == NULL) {
        result = PEP_OUT_OF_MEMORY;
        goto unlock_netpgp;
    }
    for (_keylist = keylist; _keylist != NULL; _keylist = _keylist->next) {
        assert(_keylist->value);

        const pgp_key_t *key;
        uint8_t fpr[PGP_FINGERPRINT_SIZE];
        size_t fprlen;
        unsigned from = 0;

        if (str_to_fpr(_keylist->value, fpr, &fprlen)) {
            if ((key = (pgp_key_t *)pgp_getkeybyfpr(netpgp.io, netpgp.pubring,
                                                    fpr, fprlen, &from, NULL,
                                                    /* reject revoked, accept expired */
                                                    1,0)) == NULL) {
                result = PEP_KEY_NOT_FOUND;
                goto free_rcpts;
            }
        }else{
            result = PEP_ILLEGAL_VALUE;
            goto free_rcpts;
        }

        /* Signer is the first key in the list */
        if(signer == NULL){
            from = 0;
            signer = (pgp_key_t *)pgp_getkeybyfpr(netpgp.io, netpgp.secring,
                                                  fpr, fprlen,
                                                  &from,
                                                  NULL,
                                                  0,0); /* accept any */
            if(signer == NULL){
                result = PEP_KEY_NOT_FOUND;
                goto free_rcpts;
            }
        }

        // add key to recipients/signers
        pgp_keyring_add(rcpts, key);
        if(rcpts->keys == NULL){
            result = PEP_OUT_OF_MEMORY;
            goto free_rcpts;
        }
    }

    /* Empty keylist ?*/
    if(rcpts->keyc == 0){
        result = PEP_ILLEGAL_VALUE;
        goto free_rcpts;
    }

    seckey = pgp_key_get_certkey(signer);

    /* No signig key. Revoked ? */
    if(seckey == NULL){
        result = PEP_GET_KEY_FAILED;
        goto free_rcpts;
    }

    hashalg = netpgp_getvar(&netpgp, "hash");

    const char *stext;
    size_t ssize;
    unsigned encrypt_raw_packet;
   
    if (do_sign) {  
        // Sign data
        signedmem = pgp_sign_buf(netpgp.io, ptext, psize, seckey,
                    time(NULL), /* birthtime */
                    0 /* duration */,
                    hashalg,
                    0 /* armored */,
                    0 /* cleartext */);

        if (!signedmem) {
            result = PEP_UNENCRYPTED;
            goto free_rcpts;
        }
        stext = (char*) pgp_mem_data(signedmem);
        ssize = pgp_mem_len(signedmem);
        encrypt_raw_packet = 1 /* takes raw OpenPGP message */;
    } else {
        stext = ptext;
        ssize = psize;
        encrypt_raw_packet = 0 /* not a raw OpenPGP message */;
    }

    // Encrypt (maybe) signed data

    cmem = pgp_encrypt_buf(netpgp.io, stext,
            ssize, rcpts, 1 /* armored */,
            netpgp_getvar(&netpgp, "cipher"),
            encrypt_raw_packet);

    if (cmem == NULL) {
        result = PEP_OUT_OF_MEMORY;
        goto free_signedmem;
    }else{

        char *_buffer = NULL;
        size_t length = pgp_mem_len(cmem);

        // Allocate transferable buffer
        _buffer = malloc(length + 1);
        assert(_buffer);
        if (_buffer == NULL) {
            result = PEP_OUT_OF_MEMORY;
            goto free_cmem;
        }

        memcpy(_buffer, pgp_mem_data(cmem), length);

        *ctext = _buffer;
        *csize = length;
        (*ctext)[*csize] = 0; // safeguard for naive users
        result = PEP_STATUS_OK;
    }

free_cmem :
    pgp_memory_free(cmem);
free_signedmem :
    if (do_sign) {
        pgp_memory_free(signedmem);
    }
free_rcpts :
    pgp_keyring_free(rcpts);
unlock_netpgp:
    pthread_mutex_unlock(&netpgp_mutex);

    return result;
}


PEP_STATUS pgp_sign_only(
    PEP_SESSION session, const char* fpr, const char *ptext,
    size_t psize, char **stext, size_t *ssize
    )
{
    pgp_key_t *signer = NULL;
    pgp_seckey_t *seckey = NULL;
    pgp_memory_t *signedmem = NULL;
    pgp_memory_t *text = NULL;
	pgp_output_t *output;
    
    const char *hashalg;
    pgp_keyring_t *snrs;

	pgp_create_sig_t	*sig;
	uint8_t	keyid[PGP_KEY_ID_SIZE];

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

    uint8_t uint_fpr[PGP_FINGERPRINT_SIZE];
    size_t fprlen;
    unsigned from = 0;

    if (str_to_fpr(fpr, uint_fpr, &fprlen)) {
        if ((signer = (pgp_key_t *)pgp_getkeybyfpr(netpgp.io, netpgp.secring,
                                                uint_fpr, fprlen, &from, NULL,
                                                /* reject revoked and expired */
                                                1,1)) == NULL) {
            result = PEP_KEY_NOT_FOUND;
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

    hashalg = netpgp_getvar(&netpgp, "hash");
    
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
    PEP_STATUS result;
    result = _encrypt_and_sign(session, keylist, ptext, psize, ctext, csize,
                               true);
    return result;
}

PEP_STATUS pgp_encrypt_only(
        PEP_SESSION session, const stringlist_t *keylist, const char *ptext,
        size_t psize, char **ctext, size_t *csize
    )
{
    PEP_STATUS result;
    result = _encrypt_and_sign(session, keylist, ptext, psize, ctext, csize,
                               false);
    return result;
}


PEP_STATUS pgp_generate_keypair(
    PEP_SESSION session, pEp_identity *identity
    )
{
    pgp_key_t	newseckey;
    pgp_key_t	*newpubkey;

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

    hashalg = netpgp_getvar(&netpgp, "hash");
    cipher = netpgp_getvar(&netpgp, "cipher");

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
            netpgp.pubring,
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
    if (!pgp_keyring_add(netpgp.secring, &newseckey)){
        result = PEP_OUT_OF_MEMORY;
        goto delete_pubkey;
    }

    // save rings
    if (netpgp_save_pubring(&netpgp) && netpgp_save_secring(&netpgp))
    {
        char *fprstr = NULL;
        fpr_to_str(&fprstr,
                   newseckey.pubkeyfpr.fingerprint,
                   newseckey.pubkeyfpr.length);

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
    ((pgp_keyring_t *)netpgp.secring)->keyc--;
delete_pubkey:
    pgp_deletekeybyfpr(netpgp.io,
                    (pgp_keyring_t *)netpgp.pubring,
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
    uint8_t fpr[PGP_FINGERPRINT_SIZE];
    size_t length;

    PEP_STATUS result;

    assert(session);
    assert(fprstr);

    if (!session || !fprstr)
        return PEP_ILLEGAL_VALUE;

    if(pthread_mutex_lock(&netpgp_mutex)){
        return PEP_UNKNOWN_ERROR;
    }

    if (str_to_fpr(fprstr, fpr, &length)) {
        unsigned insec = pgp_deletekeybyfpr(netpgp.io,
                                (pgp_keyring_t *)netpgp.secring,
                                (const uint8_t *)fpr, length);
        unsigned inpub = pgp_deletekeybyfpr(netpgp.io,
                                (pgp_keyring_t *)netpgp.pubring,
                                (const uint8_t *)fpr, length);
        if(!insec && !inpub){
            result = PEP_KEY_NOT_FOUND;
            goto unlock_netpgp;
        } else {
            result = PEP_STATUS_OK;
        }
    }else{
        result = PEP_OUT_OF_MEMORY;
        goto unlock_netpgp;
    }

    // save rings
    if (netpgp_save_pubring(&netpgp) &&
        netpgp_save_secring(&netpgp))
    {
        result = PEP_STATUS_OK;
    }else{
        result = PEP_UNKNOWN_ERROR;
    }

unlock_netpgp:
    pthread_mutex_unlock(&netpgp_mutex);

    return result;
}

#define ARMOR_KEY_HEAD    "^-----BEGIN PGP (PUBLIC|PRIVATE) KEY BLOCK-----"_ENDL
PEP_STATUS pgp_import_keydata(
        PEP_SESSION session,
        const char *key_data,
        size_t size,
        identity_list **private_idents
    )
{
    pgp_memory_t *mem;

    PEP_STATUS result = PEP_STATUS_OK;

    assert(session);
    assert(key_data);

    // reporting imported private keys not supported
    // stub code to be reomoved
    if(private_idents)
        *private_idents = NULL;

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

    if (pgp_keyring_read_from_mem(netpgp.io, netpgp.pubring, netpgp.secring,
                                  _armoured(key_data, size, ARMOR_KEY_HEAD),
                                  mem) == 0){
        result = PEP_ILLEGAL_VALUE;
    }

    pgp_memory_free(mem);

    // save rings
    if (netpgp_save_pubring(&netpgp) &&
        netpgp_save_secring(&netpgp))
    {
        // we never really know if a key was imported. MEH.
        result = PEP_KEY_IMPORT_STATUS_UNKNOWN;
    }else{
        result = PEP_UNKNOWN_ERROR;
    }

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
    pgp_key_t *key;
    uint8_t fpr[PGP_FINGERPRINT_SIZE];
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
        srcring = netpgp.secring;
    else
        srcring = netpgp.pubring;
    
    if (!session || !fprstr || !key_data || !size)
        return PEP_ILLEGAL_VALUE;

    if(pthread_mutex_lock(&netpgp_mutex)){
        return PEP_UNKNOWN_ERROR;
    }

    if (str_to_fpr(fprstr, fpr, &fprlen)) {
        unsigned from = 0;

        if ((key = (pgp_key_t *)pgp_getkeybyfpr(netpgp.io, srcring,
                                                fpr, fprlen, &from,
                                                NULL,0,0)) == NULL) {
            result = PEP_KEY_NOT_FOUND;
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

static size_t
HKPAnswerWriter(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct HKP_answer *mem = (struct HKP_answer *)userp;

  mem->memory = realloc(mem->memory, mem->size + realsize + 1);
  if(mem->memory == NULL) {
    mem->size = 0;
    return 0;
  }

  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;

  return realsize;
}


PEP_STATUS pgp_recv_key(PEP_SESSION session, const char *pattern)
{
    assert(!"pgp_recv_key not implemented");
    return PEP_UNKNOWN_ERROR;
}

typedef PEP_STATUS (*find_key_cb_t)(void*, pgp_key_t *);

static PEP_STATUS find_keys_do(pgp_keyring_t* keyring,
        const char *pattern, find_key_cb_t cb, void* cb_arg)
{
    uint8_t fpr[PGP_FINGERPRINT_SIZE];
    size_t length;
    pgp_key_t *key;

    PEP_STATUS result;

    // Try find a fingerprint in pattern
    if (str_to_fpr(pattern, fpr, &length)) {
        unsigned from = 0;


        // Only one fingerprint can match
        if ((key = (pgp_key_t *)pgp_getkeybyfpr(
                        netpgp.io,
                        keyring,
                        (const uint8_t *)fpr, length,
                        &from,
                        NULL, 0, 0)) == NULL) {

            return PEP_KEY_NOT_FOUND;
        }

        result = cb(cb_arg, key);

    } else {
        // Search by name for pattern. Can match many.
        unsigned from = 0;
        result = PEP_KEY_NOT_FOUND;
        while((key = (pgp_key_t *)pgp_getnextkeybyname(
                        netpgp.io,
                        keyring,
			            (const char *)pattern,
                        &from)) != NULL) {

            result = cb(cb_arg, key);
            if (result != PEP_STATUS_OK)
                break;

            from++;
        }
    }

    return result;
}

static PEP_STATUS add_key_fpr_to_stringlist(void *arg, pgp_key_t *key)
{
    stringlist_t **keylist = arg;
    char *newfprstr = NULL;

    fpr_to_str(&newfprstr,
               key->pubkeyfpr.fingerprint,
               key->pubkeyfpr.length);

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

static PEP_STATUS add_secret_key_fpr_to_stringlist(void *arg, pgp_key_t *key)
{
    if (pgp_is_key_secret(key)) {
        stringlist_t **keylist = arg;
        char *newfprstr = NULL;

        fpr_to_str(&newfprstr,
                key->pubkeyfpr.fingerprint,
                key->pubkeyfpr.length);

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
    stringpair_list_t** keyinfo_list = (stringpair_list_t**)arg;
    stringpair_t* pair = NULL;
    char* id_fpr = NULL;
    char* primary_userid = (char*)pgp_key_get_primary_userid(key);

// Unused:
//    bool key_revoked = false;

//    PEP_STATUS key_status = pgp_key_revoked(session, id_fpr, &key_revoked);

//    if (key_revoked || key_status == PEP_GET_KEY_FAILED)
//        return PEP_STATUS_OK; // we just move on

    fpr_to_str(&id_fpr, key->pubkeyfpr.fingerprint,
                key->pubkeyfpr.length);

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

    result = find_keys_do((pgp_keyring_t *)netpgp.pubring,
                          pattern, &add_key_fpr_to_stringlist, &_k);

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

static PEP_STATUS send_key_cb(void *arg, pgp_key_t *key)
{
    char *buffer = NULL;
    size_t buflen = 0;
    PEP_STATUS result;
    stringlist_t *encoded_keys;
    encoded_keys = (stringlist_t*)arg;

    result = _export_keydata(key, &buffer, &buflen);

    if(result == PEP_STATUS_OK){
        char *encoded_key = curl_escape(buffer, (int)buflen);
        if(!encoded_key){
            result = PEP_OUT_OF_MEMORY;
            goto free_buffer;
        }
        size_t encoded_key_len = strlen(encoded_key);

        char *request = calloc(1, HKP_REQ_PREFIX_LEN + encoded_key_len + 1);
        if(!request){
            result = PEP_OUT_OF_MEMORY;
            goto free_encoded_key;
        }

        memcpy(request, HKP_REQ_PREFIX, HKP_REQ_PREFIX_LEN);
        memcpy(request + HKP_REQ_PREFIX_LEN, encoded_key, encoded_key_len);
        request[HKP_REQ_PREFIX_LEN + encoded_key_len] = '\0';

        if(!stringlist_add(encoded_keys, request)){
            result = PEP_OUT_OF_MEMORY;
        }
        free(request);

free_encoded_key:
        curl_free(encoded_key);

free_buffer:
        free(buffer);
    }

    return result;
}

PEP_STATUS pgp_send_key(PEP_SESSION session, const char *pattern)
{
    assert(!"pgp_send_key not implemented");
    return PEP_UNKNOWN_ERROR;
}


PEP_STATUS pgp_get_key_rating(
    PEP_SESSION session,
    const char *fprstr,
    PEP_comm_type *comm_type
    )
{
    pgp_key_t *key;
    uint8_t fpr[PGP_FINGERPRINT_SIZE];
    unsigned from = 0;
    size_t length;


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

    if (!str_to_fpr(fprstr, fpr, &length)) {
        status = PEP_ILLEGAL_VALUE;
        goto unlock_netpgp;
    }

    key = pgp_getkeybyfpr(
           netpgp.io,
           netpgp.pubring,
           fpr, length, &from, NULL,0,0);

    if(key == NULL)
    {
        status = PEP_KEY_NOT_FOUND;
        goto unlock_netpgp;
    }

    switch(pgp_key_get_rating(key)){
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


    if (!str_to_fpr(fprstr, fpr, &length)) {
        status = PEP_ILLEGAL_VALUE;
        goto unlock_netpgp;
    }

    pkey = pgp_getkeybyfpr(
                          netpgp.io,
                          netpgp.pubring,
                          fpr, length, &from, NULL,
                          1, 0); /* reject revoked, accept expired */

    if(pkey == NULL)
    {
        status = PEP_KEY_NOT_FOUND;
        goto unlock_netpgp;
    }

    from = 0;
    skey = pgp_getkeybyfpr(
                           netpgp.io,
                           netpgp.secring,
                           fpr, length, &from, NULL,
                           1, 0); /* reject revoked, accept expired */

    if(skey == NULL)
    {
        status = PEP_KEY_NOT_FOUND;
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
    if (netpgp_save_pubring(&netpgp) &&
        netpgp_save_secring(&netpgp))
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
    uint8_t fpr[PGP_FINGERPRINT_SIZE];
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
    if (!str_to_fpr(fprstr, fpr, &length)) {
        status = PEP_ILLEGAL_VALUE;
        goto unlock_netpgp;
    }

    pgp_key_t *pkey = pgp_getkeybyfpr(
                           netpgp.io,
                           netpgp.pubring,
                           fpr, length, &from, NULL,
                           1, 0); /* reject revoked, accept expired */

    if(pkey == NULL)
    {
        status = PEP_KEY_NOT_FOUND;
        goto unlock_netpgp;
    }

    from = 0;
    pgp_key_t *skey = pgp_getkeybyfpr(
                           netpgp.io,
                           netpgp.secring,
                           fpr, length, &from, NULL,
                           1, 0); /* reject revoked, accept expired */

    if(skey == NULL)
    {
        status = PEP_KEY_NOT_FOUND;
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
    uint8_t fpr[PGP_FINGERPRINT_SIZE];
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

    if (!str_to_fpr(fprstr, fpr, &length)) {
        status = PEP_ILLEGAL_VALUE;
        goto unlock_netpgp;
    }

    key = pgp_getkeybyfpr(
           netpgp.io,
           netpgp.pubring,
           fpr, length, &from, NULL,0,0);

    if (key)
    {
        *created = (time_t) key->key.pubkey.birthtime;
    }
    else
    {
        status = PEP_KEY_NOT_FOUND;
        goto unlock_netpgp;
    }



unlock_netpgp:
    pthread_mutex_unlock(&netpgp_mutex);

    return status;
}


PEP_STATUS pgp_list_keyinfo(
        PEP_SESSION session, const char* pattern, stringpair_list_t** keyinfo_list)
{

    if (!session || !keyinfo_list)
        return PEP_UNKNOWN_ERROR;

    if (pthread_mutex_lock(&netpgp_mutex))
    {
        return PEP_UNKNOWN_ERROR;
    }

// Unused:
//    pgp_key_t *key;

    PEP_STATUS result;

    result = find_keys_do((pgp_keyring_t *)netpgp.pubring,
                          pattern, &add_keyinfo_to_stringpair_list, (void*)keyinfo_list);

    if (!keyinfo_list)
        result = PEP_KEY_NOT_FOUND;

    pthread_mutex_unlock(&netpgp_mutex);

    return result;
}

/* copied from find_keys, but we need to use a callback that filters. */
PEP_STATUS pgp_find_private_keys(
    PEP_SESSION session, const char *pattern, stringlist_t **keylist)
{
    stringlist_t *_keylist, *_k;

    PEP_STATUS result;

    assert(session);
    assert(keylist);

    if (!session || !keylist )
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

    result = find_keys_do((pgp_keyring_t *)netpgp.secring,
                          pattern, &add_secret_key_fpr_to_stringlist, &_k);

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
    bool *has_private) {
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
    return PEP_STATUS_OK;
}
