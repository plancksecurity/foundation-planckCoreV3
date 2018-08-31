#ifndef PEP_TEST_UTILS_H
#define PEP_TEST_UTILS_H

#include <string>
#include <stdlib.h>
#include <sys/stat.h>
#include <ftw.h>

#include "pEpEngine.h"
#include "message_api.h"

void test_init();

bool file_exists(std::string filename);

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

// Grabs a new uuid for your randomish string needs.
char* get_new_uuid();

bool slurp_message_and_import_key(PEP_SESSION session, const char* message_fname, std::string& message, const char* key_filename);

int util_delete_filepath(const char *filepath, 
                         const struct stat *file_stat, 
                         int ftw_info, 
                         struct FTW * ftw_struct);
        
#endif
