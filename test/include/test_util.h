#ifndef PEP_TEST_UTILS_H
#define PEP_TEST_UTILS_H

#include <string>
#include "pEpEngine.h"
#include "message_api.h"

void test_init();

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

#endif
