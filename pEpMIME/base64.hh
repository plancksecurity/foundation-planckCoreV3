// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef PEP_MIME_BASE64_HH
#define PEP_MIME_BASE64_HH

#include <string>
#include "pEpMIME_internal.hh"

namespace pEpMIME
{
namespace base64
{

// Decodes base64-encoded 'input', skip whitespaces, throw std::runtime_error if an illegal character found in string
std::string decode(const std::string& input);

// encodes into output string
void encode(std::string& output, sv input, int line_length, sv delimiter);

inline
std::string encode(sv input)
{
    std::string ret;
    encode(ret, input, -1, sv{} );
    return ret;
}


///////////////////////////////////////
// Low-level interface, necessary to use base64-encoding also from C
template<class InIter, class OutIter, class OutIter2>
void decode_iter(InIter begin, InIter end, OutIter& out, OutIter2 out_end);



} // end of namespace pEpMIME::base64
} // end of namespace pEpMIME

#endif // PEP_MIME_BASE64_HH
