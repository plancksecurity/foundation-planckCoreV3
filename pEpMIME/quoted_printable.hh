// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef PEP_MIME_QUOTED_PRINTABLE_HH
#define PEP_MIME_QUOTED_PRINTABLE_HH

#include <string>
#include "pEpMIME_internal.hh"

namespace pEpMIME
{
namespace qp
{

    enum HeaderType
    {// the bigger the stricter / smaller the allowed (=unencoded) charset
        Text = 1, // free text header lines, e.g. "Subject:"
        Word = 2, // used for atoms, dot-atoms etc. e.g. display names
    };

constexpr const unsigned MaxLineLength = 76;


// Decodes "quoted printable"-encoded 'input', throw std::runtime_error if an illegal character found in string
std::string decode(sv input);

// Encodes into "quoted printable" encoding, with optional line breaks
std::string encode(sv input);

///////////////////////////////////////
// Low-level interface, necessary to use base64-encoding also from C
template<class InIter, class OutIter, class OutIter2>
void decode_iter(InIter begin, InIter end, OutIter& out, OutIter2 out_end);


// For RFC-2047-compliant header fields "quoted printable" differs a bit:
// Decodes "quoted printable"-encoded 'input', throw std::runtime_error if an illegal character found in string
std::string decode_header(sv input);

// Encodes into "quoted printable" encoding, with optional line breaks after 78 characters
// If "name" is non-empty, add the name + ": " in front of the encoded header line.
std::string encode_header(sv name, sv value, HeaderType type);

} // end of namespace pEpMIME::qp
} // end of namespace pEpMIME

#endif // PEP_MIME_QUOTED_PRINTABLE_HH
