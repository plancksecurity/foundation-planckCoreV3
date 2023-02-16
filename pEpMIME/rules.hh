// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef PEP_MIME_RULES_HH
#define PEP_MIME_RULES_HH

#include "pEpMIME_internal.hh"
#include <boost/spirit/include/qi_rule.hpp>

namespace qi = boost::spirit::qi;

// px::_a = px::_1 does not work from vector<char> to string. So this helps:
namespace std
{
    string& operator<<=(string& s, const vector<char>& v);
}

namespace pEpMIME
{

typedef qi::rule<sv::const_iterator, std::string()> Rule;
typedef qi::rule<sv::const_iterator, qi::unused_type()> URule;

// Rule with Local variables
template<class T, class... LOCALS>
using TRule = qi::rule<sv::const_iterator, T(), qi::locals<LOCALS...> >;


struct CommentRules
{
    CommentRules();

    Rule vchar; // U+0021 ... U+007E - visible ASCII chars.
    Rule ws;
    Rule qpair; // quoted pair
    Rule fws; // folding/collapsed whitespaces

// Comments
    URule ctext;
    URule ccontent;
     Rule comment;
     Rule cfws;
     Rule ocfws;
};


struct BasicRules : public CommentRules
{
    BasicRules();

// Atoms
    const Rule atext;
    const Rule atom;
    const Rule atom_nows;
    const Rule dot_atom_text;

    const TRule<std::string, std::string, std::string, std::string> encoded_word;
    const Rule encoded_words;
    
// not used in atext
    const Rule aspecials;

// Text in quoted strings
    const Rule qtext;
    const Rule qcontent;
    const Rule quoted_string;

// all together
    const Rule word;
    const Rule phrase;
    const Rule unstructured;
};


bool match(const Rule& rule, sv content);

} // end of namespace pEpMIME


#endif // PEP_MIME_RULES_HH
