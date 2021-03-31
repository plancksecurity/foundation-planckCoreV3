#ifndef PEP_TEST_UTILS_H
#define PEP_TEST_UTILS_H

#include <string>
#include <stdlib.h>
#include <sys/stat.h>
#include <ftw.h>
#include <iostream>
#include <vector>

#include "pEpEngine.h"
#include "message_api.h"
#include "aux_mime_msg.h"
#include "mime.h"

#include <gtest/gtest.h>

void test_init();

bool file_exists(std::string filename);
bool is_pEpmsg(const message *msg); // duplicates static func in message_api.c, fyi

#ifndef ASSERT_OK
#define ASSERT_OK ASSERT_EQ(status, PEP_STATUS_OK)
#endif

extern std::string _main_test_home_dir;

#ifndef DEBUG_OUTPUT
extern std::ostream output_stream;
#else
#define output_stream std::cerr
#endif

std::string get_main_test_home_dir();
std::string random_string( size_t length );

typedef enum _pEp_test_ident_preset {
    ALICE,
    APPLE,
    BOB,
    CAROL,
    DAVE,
    ERIN,
    FRANK,
    GABRIELLE,
    JOHN,
    ALEX,
    ALEX_0,
    ALEX_1,
    ALEX_2,
    ALEX_3,
    ALEX_4,
    ALEX_5,
    ALEX_6A,
    ALEX_6B,
    ALEX_6C,
    ALEX_6D,
    BELLA,
    FENRIS,
    SERCULLEN,
    INQUISITOR,
    BERND
} pEp_test_ident_preset;

PEP_STATUS set_up_preset(PEP_SESSION session,
                         pEp_test_ident_preset preset_name,
                         bool set_identity, 
                         bool set_pep,
                         bool trust,
                         bool set_own, 
                         bool setup_private, 
                         pEp_identity** ident);


PEP_STATUS read_file_and_import_key(PEP_SESSION session, const char* fname);
PEP_STATUS set_up_ident_from_scratch(PEP_SESSION session, 
                                     const char* key_fname,
                                     const char* address,
                                     const char* fpr,
                                     const char* user_id,
                                     const char* username,
                                     pEp_identity** ret_ident,
                                     bool is_priv);

// string equality (case and non-case sensitive)
bool _streq(const char* str1, const char* str2);
bool _strceq(const char* str1, const char* str2);

// reads a whole file and returns it as std::string
// throws std::runtime_error() if the file cannot be read. Empty file is not an error.
std::string slurp(const std::string& filename);

// dumps char* to file
// throws std::runtime_error() if the file cannot be opened.
void dump_out(const char* filename, const char* outdata);

// Returns the string value of the input rating enum value. 
const char* tl_rating_string(PEP_rating rating);

// Returns the string value of the input comm_type enum value. 
const char* tl_ct_string(PEP_comm_type ct);

// Returns the string value of the input status enum value. 
const char* tl_status_string(PEP_STATUS status);

std::string tl_ident_flags_String(identity_flags_t fl);

// Grabs a new uuid for your randomish string needs.
char* get_new_uuid();

bool slurp_and_import_key(PEP_SESSION session, const char* key_filename);

bool slurp_message_and_import_key(PEP_SESSION session, const char* message_fname, std::string& message, const char* key_filename);

char* message_to_str(message* msg);
message* string_to_msg(std::string infile);

int util_delete_filepath(const char *filepath, 
                         const struct stat *file_stat, 
                         int ftw_info, 
                         struct FTW * ftw_struct);
                         
class NullBuffer : public std::streambuf {
    public:
        int overflow(int c);
};                         
                         
PEP_STATUS config_valid_passphrase(PEP_SESSION session, const char* fpr, std::vector<std::string> passphrases);

#ifndef ENIGMAIL_MAY_USE_THIS

// MIME_decrypt_message() - decrypt a MIME message, with MIME output
//
//  parameters:
//      session (in)            session handle
//      mimetext (in)           MIME encoded text to decrypt
//      size (in)               size of mime text to decode (in order to decrypt)
//      mime_plaintext (out)    decrypted, encoded message
//      keylist (inout)         in: stringlist with additional keyids for reencryption if needed
//                                  (will be freed and replaced with output keylist)
//                              out: stringlist with keyids
//      rating (out)            rating for the message
//      flags (inout)           flags to signal special decryption features (see below)
//      modified_src (out)      modified source string, if decrypt had reason to change it
//
//  return value:
//      decrypt status          if everything worked with MIME encode/decode, 
//                              the status of the decryption is returned 
//                              (PEP_STATUS_OK or decryption error status)
//      PEP_BUFFER_TOO_SMALL    if encoded message size is too big to handle
//      PEP_CANNOT_CREATE_TEMP_FILE
//                              if there are issues with temp files; in
//                              this case errno will contain the underlying
//                              error
//      PEP_OUT_OF_MEMORY       if not enough memory could be allocated
//
//  flag values:
//      in:
//          PEP_decrypt_flag_untrusted_server
//              used to signal that decrypt function should engage in behaviour
//              specified for when the server storing the source is untrusted.
//      out:
//          PEP_decrypt_flag_own_private_key
//              private key was imported for one of our addresses (NOT trusted
//              or set to be used - handshake/trust is required for that)
//          PEP_decrypt_flag_src_modified
//              indicates that the modified_src field should contain a modified
//              version of the source, at the moment always as a result of the
//              input flags. 
//          PEP_decrypt_flag_consume
//              used by sync 
//          PEP_decrypt_flag_ignore
//              used by sync 
// 
//  caveat:
//      the decrypted, encoded mime text will go to the ownership of the caller; mimetext
//      will remain in the ownership of the caller
PEP_STATUS MIME_decrypt_message(
    PEP_SESSION session,
    const char *mimetext,
    size_t size,
    char** mime_plaintext,
    stringlist_t **keylist,
    PEP_rating *rating,
    PEP_decrypt_flags_t *flags,
    char** modified_src
);

// MIME_encrypt_message() - encrypt a MIME message, with MIME output
//
//  parameters:
//      session (in)            session handle
//      mimetext (in)           MIME encoded text to encrypt
//      size (in)               size of input mime text
//      extra (in)              extra keys for encryption
//      mime_ciphertext (out)   encrypted, encoded message
//      enc_format (in)         encrypted format
//      flags (in)              flags to set special encryption features
//
//  return value:
//      PEP_STATUS_OK           if everything worked
//      PEP_BUFFER_TOO_SMALL    if encoded message size is too big to handle
//      PEP_CANNOT_CREATE_TEMP_FILE
//                              if there are issues with temp files; in
//                              this case errno will contain the underlying
//                              error
//      PEP_OUT_OF_MEMORY       if not enough memory could be allocated
//
//  caveat:
//      the encrypted, encoded mime text will go to the ownership of the caller; mimetext
//      will remain in the ownership of the caller
DYNAMIC_API PEP_STATUS MIME_encrypt_message(
    PEP_SESSION session,
    const char *mimetext,
    size_t size,
    stringlist_t* extra,
    char** mime_ciphertext,
    PEP_enc_format enc_format,
    PEP_encrypt_flags_t flags
);


// MIME_encrypt_message_for_self() - encrypt MIME message for user's identity only,
//                              ignoring recipients and other identities from
//                              the message, with MIME output
//  parameters:
//      session (in)            session handle
//      target_id (in)          self identity this message should be encrypted for
//      mimetext (in)           MIME encoded text to encrypt
//      size (in)               size of input mime text
//      extra (in)              extra keys for encryption
//      mime_ciphertext (out)   encrypted, encoded message
//      enc_format (in)         encrypted format
//      flags (in)              flags to set special encryption features
//
//  return value:
//      PEP_STATUS_OK           if everything worked
//      PEP_BUFFER_TOO_SMALL    if encoded message size is too big to handle
//      PEP_CANNOT_CREATE_TEMP_FILE
//                              if there are issues with temp files; in
//                              this case errno will contain the underlying
//                              error
//      PEP_OUT_OF_MEMORY       if not enough memory could be allocated
//
//  caveat:
//      the encrypted, encoded mime text will go to the ownership of the caller; mimetext
//      will remain in the ownership of the caller
PEP_STATUS MIME_encrypt_message_for_self(
    PEP_SESSION session,
    pEp_identity* target_id,
    const char *mimetext,
    size_t size,
    stringlist_t* extra,
    char** mime_ciphertext,
    PEP_enc_format enc_format,
    PEP_encrypt_flags_t flags
);

#endif
#endif
