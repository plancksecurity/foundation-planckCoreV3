#include <string>
#include "pEpEngine.h"
#include "message_api.h"

// reads a whole file and returns it as std::string
// throws std::runtime_error() if the file cannot be read. Empty file is not an error.
std::string slurp(const std::string& filename);

// Returns the string value of the input rating enum value. 
const char* tl_rating_string(PEP_rating rating);

// Returns the string value of the input comm_type enum value. 
const char* tl_ct_string(PEP_comm_type ct);

// Returns the string value of the input status enum value. 
const char* tl_status_string(PEP_STATUS status);
