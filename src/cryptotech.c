#include "pEp_internal.h"

#ifdef USE_GPG
#include "pgp_gpg.h"
#elif USE_NETPGP
#include "pgp_netpgp.h"
#endif

#include <stdlib.h>
#include <memory.h>
#include <assert.h>

PEP_STATUS init_cryptotech(PEP_SESSION session, bool in_first)
{
    static PEP_cryptotech_t cryptotech[PEP_crypt__count];
    PEP_STATUS status = PEP_STATUS_OK;

    assert(PEP_crypt__count == 2);

    if (in_first) {
        memset(cryptotech, 0, sizeof(PEP_cryptotech_t) * PEP_crypt__count);

        cryptotech[PEP_crypt_none].id = PEP_crypt_none;
        cryptotech[PEP_crypt_none].unconfirmed_comm_type = PEP_ct_no_encryption;
        cryptotech[PEP_crypt_none].confirmed_comm_type = PEP_ct_no_encryption;

        cryptotech[PEP_crypt_OpenPGP].id = PEP_crypt_OpenPGP;
        cryptotech[PEP_crypt_OpenPGP].unconfirmed_comm_type = PEP_ct_OpenPGP_unconfirmed;
        cryptotech[PEP_crypt_OpenPGP].confirmed_comm_type = PEP_ct_OpenPGP;
        cryptotech[PEP_crypt_OpenPGP].decrypt_and_verify = pgp_decrypt_and_verify;
        cryptotech[PEP_crypt_OpenPGP].encrypt_and_sign = pgp_encrypt_and_sign;
        cryptotech[PEP_crypt_OpenPGP].verify_text = pgp_verify_text;
        cryptotech[PEP_crypt_OpenPGP].delete_keypair = pgp_delete_keypair;
        cryptotech[PEP_crypt_OpenPGP].export_key = pgp_export_key;
        cryptotech[PEP_crypt_OpenPGP].find_keys = pgp_find_keys;
        cryptotech[PEP_crypt_OpenPGP].generate_keypair = pgp_generate_keypair;
        cryptotech[PEP_crypt_OpenPGP].get_key_rating = pgp_get_key_rating;
        cryptotech[PEP_crypt_OpenPGP].import_key = pgp_import_key;
        cryptotech[PEP_crypt_OpenPGP].recv_key = pgp_recv_key;
        cryptotech[PEP_crypt_OpenPGP].send_key = pgp_send_key;
    }

    session->cryptotech = cryptotech;

    status = pgp_init(session, in_first);
    if (status != PEP_STATUS_OK)
        goto pep_error;

    return PEP_STATUS_OK;

pep_error:
    pgp_release(session, in_first);
    return status;
}

void release_cryptotech(PEP_SESSION session, bool out_last)
{
    pgp_release(session, out_last);
}
