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
#include <netpgp/readerwriter.h>

#include <curl/curl.h>
#include <pthread.h>
#include <regex.h>

#define PEP_NETPGP_DEBUG

static netpgp_t netpgp;
static pthread_mutex_t netpgp_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t curl_mutex = PTHREAD_MUTEX_INITIALIZER;



PEP_STATUS enter_curl(PEP_SESSION session, CURL **curl){
}

PEP_STATUS pgp_init(PEP_SESSION session, bool in_first)
{
    PEP_STATUS status = PEP_STATUS_OK;
    const char *home = NULL;

    assert(session);
    if(!session) return PEP_UNKNOWN_ERROR;

    if(pthread_mutex_init(&netpgp_mutex, NULL)){
        return PEP_OUT_OF_MEMORY;
    }

    if(pthread_mutex_lock(&netpgp_mutex)){;
        return PEP_UNKNOWN_ERROR;
    }
   
    if (in_first) {
        if (strcmp(setlocale(LC_ALL, NULL), "C") == 0)
            setlocale(LC_ALL, "");

        memset(&netpgp, 0x0, sizeof(netpgp_t));


        // netpgp_setvar(&netpgp, "max mem alloc", "4194304");
        netpgp_setvar(&netpgp, "need seckey", "1");
        netpgp_setvar(&netpgp, "need userid", "1");

        // NetPGP shares home with GPG
        home = gpg_home();
        if(home){
            netpgp_set_homedir(&netpgp,(char*)home, NULL, 0);
        }else{
            status = PEP_INIT_NO_GPG_HOME;
            goto unlock_netpgp;
        }

        // pair with gpg's cert-digest-algo
        netpgp_setvar(&netpgp, "hash", "SHA256");

        // subset of gpg's personal-cipher-preferences
        // here only one cipher can be selected
        netpgp_setvar(&netpgp, "cipher", "CAST5");

        if (!netpgp_init(&netpgp)) {
            status = PEP_INIT_NETPGP_INIT_FAILED;
            goto unlock_netpgp;
        }
    }

    status = PEP_STATUS_OK;

unlock_netpgp:
    pthread_mutex_unlock(&netpgp_mutex);

    if(status != PEP_STATUS_OK){
        pgp_release(session, in_first);
    }

    return status;
}

void pgp_release(PEP_SESSION session, bool out_last)
{
    assert(session);
    if(!session) return;

    if(pthread_mutex_lock(&netpgp_mutex)){;
        return;
    }

    if (out_last){
        netpgp_end(&netpgp);
        memset(&netpgp, 0x0, sizeof(netpgp_t));
        pthread_mutex_destroy(&netpgp_mutex);
        return;
    }

    pthread_mutex_unlock(&netpgp_mutex);
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

/* return key ID's hexdump as a string */
static void id_to_str(const uint8_t *userid, char *fpr)
{
    int i;
    static const char *hexes = "0123456789abcdef";
    for (i = 0; i < 8 ; i++) {
        fpr[i * 2] = hexes[(unsigned)(userid[i] & 0xf0) >> 4];
        fpr[(i * 2) + 1] = hexes[userid[i] & 0xf];
    }
    fpr[8 * 2] = 0x0;
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
            char id[MAX_ID_LENGTH + 1];
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

            id_to_str(userid, id);

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

    if(pthread_mutex_lock(&netpgp_mutex)){;
        return PEP_UNKNOWN_ERROR;
    }

    *ptext = NULL;
    *psize = 0;
    *keylist = NULL;

    vresult = malloc(sizeof(pgp_validation_t));
    memset(vresult, 0x0, sizeof(pgp_validation_t));

    mem = pgp_decrypt_and_validate_buf(netpgp.io, vresult, ctext, csize,
                netpgp.secring, netpgp.pubring,
                _armoured(ctext, csize, ARMOR_HEAD),
                0 /* sshkeys */,
                NULL, -1, NULL  /* pass fp,attempts,cb */);
    if (mem == NULL) {
        result = PEP_OUT_OF_MEMORY;
        goto unlock_netpgp;
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
        result = _validation_results(&netpgp, vresult, &_keylist);
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

unlock_netpgp:
    pthread_mutex_unlock(&netpgp_mutex);

    return result;
}

#define ARMOR_SIG_HEAD    "^-----BEGIN PGP (SIGNATURE|SIGNED MESSAGE)-----\\s*$"
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
        return PEP_UNKNOWN_ERROR;

    if(pthread_mutex_lock(&netpgp_mutex)){;
        return PEP_UNKNOWN_ERROR;
    }

    *keylist = NULL;

    vresult = malloc(sizeof(pgp_validation_t));
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

free_keylist:
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

PEP_STATUS pgp_encrypt_and_sign(
    PEP_SESSION session, const stringlist_t *keylist, const char *ptext,
    size_t psize, char **ctext, size_t *csize
    )
{
    const pgp_key_t *keypair;
    pgp_seckey_t *seckey;
    pgp_memory_t *signedmem;
    pgp_memory_t *cmem;
    const char *userid;
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
        return PEP_UNKNOWN_ERROR;

    if(pthread_mutex_lock(&netpgp_mutex)){;
        return PEP_UNKNOWN_ERROR;
    }

    *ctext = NULL;
    *csize = 0;

    // Get signing details from netpgp
    if ((userid = netpgp_getvar(&netpgp, "userid")) == NULL || 
        (keypair = pgp_getkeybyname(netpgp.io, netpgp.secring, userid)) == NULL ||
        (seckey = pgp_decrypt_seckey(keypair, NULL /*passfp*/)) == NULL) {
        return PEP_UNKNOWN_ERROR;
    }

    hashalg = netpgp_getvar(&netpgp, "hash");
    // netpgp (l)imitation - XXX why ? 
    if (seckey->pubkey.alg == PGP_PKA_DSA) {
        hashalg = "sha1";
    }

    // Sign data
    signedmem = pgp_sign_buf(netpgp.io, ptext, psize, seckey,
                time(NULL), /* birthtime */
                0 /* duration */,
                hashalg, 
                0 /* armored */,
                0 /* cleartext */);

    pgp_forget(seckey, (unsigned)sizeof(*seckey));

    if (!signedmem) {
        result = PEP_UNENCRYPTED;
        goto unlock_netpgp;
    }

    // Encrypt signed data
    if ((rcpts = calloc(1, sizeof(*rcpts))) == NULL) {
        result = PEP_OUT_OF_MEMORY;
        goto free_signedmem;
    }
    for (_keylist = keylist; _keylist != NULL; _keylist = _keylist->next) {
        assert(_keylist->value);
        // get key from netpgp's pubring
        const pgp_key_t *key;
        key = pgp_getkeybyname(netpgp.io,
                               netpgp.pubring,
                               _keylist->value);

        if(key == NULL){
            result = PEP_KEY_NOT_FOUND;
            goto free_rcpts;
        }
#ifdef PEP_NETPGP_DEBUG
        pgp_print_keydata(netpgp.io, netpgp.pubring, key,
                          "recipient pubkey ", &key->key.pubkey, 0);
#endif //PEP_NETPGP_DEBUG

        // add key to recipients/signers
        pgp_keyring_add(rcpts, key);
        if(rcpts->keys == NULL){
            result = PEP_OUT_OF_MEMORY;
            goto free_signedmem;
        }
    }

    cmem = pgp_encrypt_buf(netpgp.io, pgp_mem_data(signedmem),
            pgp_mem_len(signedmem), rcpts, 1 /* armored */,
            netpgp_getvar(&netpgp, "cipher"), 
            1 /* takes raw OpenPGP message */);

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
free_rcpts :
    pgp_keyring_free(rcpts);
free_signedmem :
    pgp_memory_free(signedmem);
unlock_netpgp:
    pthread_mutex_unlock(&netpgp_mutex);

    return result;
}

/* return the hexdump as a string */
static unsigned
fpr_to_str (char **str, const uint8_t *fpr, size_t length)
{
    unsigned i;
    int	n;

    /* 5 char per byte (hexes + space) tuple -1 space at the end + null */
    *str = malloc((length / 2) * 5 - 1 + 1);

    if(*str == NULL)
        return 0;

    for (n = 0, i = 0 ; i < length - 2; i += 2) {
    	n += snprintf(&((*str)[n]), 6, "%02x%02x ", fpr[i], fpr[i+1]);
    }
    snprintf(&((*str)[n]), 5, "%02x%02x", fpr[i], fpr[i+1]);

    return 1;
}

static unsigned
str_to_fpr (const char *str, uint8_t *fpr, size_t *length)
{
    unsigned i,j;

    *length = 0;

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

static PEP_STATUS import_key_or_keypair(netpgp_t *netpgp, pgp_key_t *newkey){
    pgp_key_t	pubkey;
    unsigned public;
    PEP_STATUS result;
    
    if ((public = (newkey->type == PGP_PTAG_CT_PUBLIC_KEY))){
        pubkey = *newkey;
    } else {
        // Duplicate key as public only
        bzero(&pubkey, sizeof(pubkey));
        if (!pgp_keydata_dup(&pubkey, newkey, 1 /* make_public */)){
            return PEP_OUT_OF_MEMORY;
        }
    }

    // Append key to netpgp's rings (key ownership transfered)
    if (!public && !pgp_keyring_add(netpgp->secring, newkey)){
        result = PEP_OUT_OF_MEMORY;
        goto free_pubkey;
    } else if (!pgp_keyring_add(netpgp->pubring, &pubkey)){
        result = PEP_OUT_OF_MEMORY;
        goto pop_secring;
    }

    // save rings 
    if (netpgp_save_pubring(netpgp) && 
        (!public || netpgp_save_secring(netpgp)))
    {
        /* free nothing, everything transfered */
        return PEP_STATUS_OK;
    } else {
        /* XXX in case only pubring save succeed
         * pubring file is left as-is, but backup restore
         * could be attempted if such corner case matters */
        result = PEP_UNKNOWN_ERROR;
    }

pop_pubring:
    ((pgp_keyring_t *)netpgp->pubring)->keyc--;
pop_secring:
    ((pgp_keyring_t *)netpgp->secring)->keyc--;
free_pubkey:
    pgp_key_free(&pubkey);

    return result;
}

PEP_STATUS pgp_generate_keypair(
    PEP_SESSION session, pEp_identity *identity
    )
{
    pgp_key_t	newkey;

    PEP_STATUS result;
    char newid[1024];
    const char *hashalg;
    const char *cipher;
    char *fprstr = NULL;

    assert(session);
    assert(identity);
    assert(identity->address);
    assert(identity->fpr == NULL);
    assert(identity->username);

    if(!session || !identity || 
       !identity->address || identity->fpr || !identity->username)
        return PEP_UNKNOWN_ERROR;

    if(pthread_mutex_lock(&netpgp_mutex)){;
        return PEP_UNKNOWN_ERROR;
    }

    if(snprintf(newid, sizeof(newid),
        "%s <%s>", identity->username, identity->address) >= sizeof(newid)){
        result =  PEP_BUFFER_TOO_SMALL;
        goto unlock_netpgp;
    }
    
    hashalg = netpgp_getvar(&netpgp, "hash");
    cipher = netpgp_getvar(&netpgp, "cipher");

    bzero(&newkey, sizeof(newkey));

    // Generate the key
    if (!pgp_rsa_generate_keypair(&newkey, 4096, 65537UL, hashalg, cipher,
                                  (const uint8_t *) "", (const size_t) 0) ||
        !pgp_add_selfsigned_userid(&newkey, (uint8_t *)newid)) {
        result = PEP_CANNOT_CREATE_KEY;
        goto free_newkey;
    }

    // TODO "Expire-Date: 1y\n";

    fpr_to_str(&fprstr,
               newkey.sigfingerprint.fingerprint,
               newkey.sigfingerprint.length);
    if (fprstr == NULL) {
        result = PEP_OUT_OF_MEMORY;
        goto free_newkey;
    } 

    result = import_key_or_keypair(&netpgp, &newkey);

    if (result == PEP_STATUS_OK) {
        identity->fpr = fprstr;
        /* free nothing, everything transfered */
        result = PEP_STATUS_OK;
        goto unlock_netpgp;
    }

free_fprstr:
    free(fprstr);
free_newkey:
    pgp_key_free(&newkey);
unlock_netpgp:
    pthread_mutex_unlock(&netpgp_mutex);

    return result;
}

PEP_STATUS pgp_delete_keypair(PEP_SESSION session, const char *fprstr)
{
    uint8_t fpr[PGP_FINGERPRINT_SIZE];
    size_t length;
    unsigned res;

    PEP_STATUS result;

    assert(session);
    assert(fpr);

    if (!session || !fpr)
        return PEP_UNKNOWN_ERROR;

    if(pthread_mutex_lock(&netpgp_mutex)){;
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

    // save rings (key ownership transfered)
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

#define ARMOR_KEY_HEAD    "^-----BEGIN PGP (PUBLIC|PRIVATE) KEY BLOCK-----\\s*$"
PEP_STATUS pgp_import_keydata(PEP_SESSION session, const char *key_data, size_t size)
{

    pgp_memory_t *mem;
    pgp_keyring_t tmpring;

    PEP_STATUS result;

    assert(session);
    assert(key_data);

    if(!session || !key_data) 
        return PEP_UNKNOWN_ERROR;

    if(pthread_mutex_lock(&netpgp_mutex)){;
        return PEP_UNKNOWN_ERROR;
    }

    mem = pgp_memory_new();
    if (mem == NULL) {
        result = PEP_OUT_OF_MEMORY;
        goto unlock_netpgp;
    }
    pgp_memory_add(mem, (const uint8_t*)key_data, size);

    bzero(&tmpring, sizeof(tmpring));

    if (pgp_keyring_read_from_mem(netpgp.io, &tmpring, 
                                  _armoured(key_data, size, ARMOR_KEY_HEAD),
                                  mem) == 0){
        result = PEP_ILLEGAL_VALUE;
    }else if (tmpring.keyc == 0){
        result = PEP_UNKNOWN_ERROR;
    }else if (tmpring.keyc > 1){
        /* too many keys given */
        /* XXX TODO accept many */
        result = PEP_ILLEGAL_VALUE;
    }else{
        result = import_key_or_keypair(&netpgp, &tmpring.keys[0]);
    }
    
    pgp_memory_free(mem);

    if (result == PEP_STATUS_OK){
        pgp_keyring_free(&tmpring);
    }else{
        pgp_keyring_purge(&tmpring);
    }

unlock_netpgp:
    pthread_mutex_unlock(&netpgp_mutex);

    return result;
}

PEP_STATUS pgp_export_keydata(
    PEP_SESSION session, const char *fprstr, char **key_data, size_t *size
    )
{
    pgp_key_t *key;
	pgp_output_t *output;
    pgp_memory_t *mem;
    uint8_t fpr[PGP_FINGERPRINT_SIZE];
    size_t fprlen;

    PEP_STATUS result;
    char *buffer;
    size_t buflen;

    assert(session);
    assert(fprstr);
    assert(key_data);
    assert(size);

    if (!session || !fprstr || !key_data || !size)
        return PEP_UNKNOWN_ERROR;

    if(pthread_mutex_lock(&netpgp_mutex)){;
        return PEP_UNKNOWN_ERROR;
    }

    if (str_to_fpr(fprstr, fpr, &fprlen)) {
        unsigned from = 0;
        if ((key = (pgp_key_t *)pgp_getkeybyfpr(netpgp.io, netpgp.pubring, 
                                                fpr, fprlen,
                                                &from, NULL)) == NULL) {
            result = PEP_KEY_NOT_FOUND;
            goto unlock_netpgp;
        }
    }else{
        result = PEP_OUT_OF_MEMORY;
        goto unlock_netpgp;
    }
    
	pgp_setup_memory_write(&output, &mem, 128);

    if (mem == NULL || output == NULL) {
        result = PEP_OUT_OF_MEMORY;
        goto unlock_netpgp;
    }

    if (!pgp_write_xfer_pubkey(output, key, 1)) {
        result = PEP_UNKNOWN_ERROR;
        goto free_mem;
    }

    buffer = NULL;
    buflen = pgp_mem_len(mem);

    // Allocate transferable buffer
    buffer = malloc(buflen + 1);
    assert(buffer);
    if (buffer == NULL) {
        result = PEP_OUT_OF_MEMORY;
        goto free_mem;
    }

    memcpy(buffer, pgp_mem_data(mem), buflen);

    *key_data = buffer;
    *size = buflen;
    (*key_data)[*size] = 0; // safeguard for naive users
    result = PEP_STATUS_OK;

free_mem :
	pgp_teardown_memory_write(output, mem);
unlock_netpgp:
    pthread_mutex_unlock(&netpgp_mutex);

    return result;
}

// "keyserver"
// "hkp://keys.gnupg.net"
PEP_STATUS pgp_recv_key(PEP_SESSION session, const char *pattern)
{
    assert(session);
    assert(pattern);

    CURL *curl;
    curl = session->ctx.curl;

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

PEP_STATUS pgp_renew_key(
        PEP_SESSION session,
        const char *fpr,
        const timestamp *ts
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    char date_text[12];

    assert(session);
    assert(fpr);

    snprintf(date_text, 12, "%.4d-%.2d-%.2d\n", ts->tm_year + 1900,
            ts->tm_mon + 1, ts->tm_mday);


        return PEP_UNKNOWN_ERROR;
    return PEP_STATUS_OK;
}

PEP_STATUS pgp_revoke_key(
        PEP_SESSION session,
        const char *fpr,
        const char *reason
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    
    assert(session);
    assert(fpr);

        return PEP_UNKNOWN_ERROR;

    return PEP_STATUS_OK;
}

PEP_STATUS pgp_key_expired(
        PEP_SESSION session,
        const char *fpr,
        bool *expired
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);
    assert(fpr);
    assert(expired);

    *expired = false;

    if (status != PEP_STATUS_OK)
        return status;

    return PEP_STATUS_OK;
}

