#ifndef PEP_MIME_HEADER_GENERATOR_HH
#define PEP_MIME_HEADER_GENERATOR_HH

#include "pEpMIME.hh"
#include "pEpMIME_internal.hh"
#include "rules.hh"

namespace pEpMIME
{

    void generate(std::string& out, sv header_name, const pEp_identity* id );
    void generate(std::string& out, sv header_name, const identity_list* il);
    
    // different header fields must fulfill different syntax rules. :-/
    void generate(std::string& out, const Rule& rule, sv header_name, const stringlist_t* sl);

    void generate_header(std::string& smsg, const message* msg);

} // end of namespace pEpMIME

#endif // PEP_MIME_HEADER_GENERATOR_HH
