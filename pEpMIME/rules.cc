// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "rules.hh"

#include <boost/spirit/include/qi.hpp>
#include <boost/spirit/include/phoenix.hpp>

#include "base64.hh"
#include "quoted_printable.hh"
#include "to_utf8.hh"

// shortcuts
namespace qi = boost::spirit::qi;
namespace px = boost::phoenix;

// px::_a = px::_1 does not work from vector<char> to string. So this helps:
namespace std
{
    string& operator<<=(string& s, const vector<char>& v)
    {
        s.clear();
        s.reserve(v.size());
        s.insert(0, v.data(), v.size());
        return s;
    }
}


namespace pEpMIME {

CommentRules::CommentRules()
: vchar { qi::char_("!-~") } // U+0021 ... U+007E - visible ASCII chars.
, ws    { qi::char_("\t ") }
, qpair { qi::lit('\\') >> (vchar | ws) } // quoted pair

, fws { (+qi::char_("\t\n\r "))[ qi::_val += " "] } // collaps multiple whitespaces into one " "
{
    const Rule cws { qi::lit("\t\n\r ") }; // comment ws -> will be thrown away later anyway

    ctext    = qi::char_ - qi::char_("()\\");  // contains whitespace and control chars, too!
    ccontent = qpair | ctext | comment.alias();
    comment  = (qi::lit('(') >> qi::hold[*ccontent] >> qi::lit(')'));
    cfws     = (+(fws | comment))[ qi::_val += ' '];
    ocfws    = (*(fws | comment))[ qi::_val += ' '];  // optional cfws, but always produce a " " on output to separate words
}


BasicRules::BasicRules()
: CommentRules()

// Atoms
, atext { qi::char_("a-zA-Z0-9!#$%&'*+/=?^_`{|}~-") } // according to RFC 5322 Section 3.2.3
, atom  { qi::omit[-ws] >> +atext >> qi::omit[-ws] }
, atom_nows { +atext }
, dot_atom_text { +atext >> *( qi::char_('.') >> +atext ) }

// RFC 2047
, encoded_word { ( qi::lit("=?")
    >> ((+qi::char_("a-zA-Z0-9_+-"))[px::ref(qi::_a) <<= qi::_1] )  // charset -> _a
    >> -( '*' >> *(qi::char_ - '?'))  // optional "language" flag, according to RFC 2184 / 2231
    >> (
            ( qi::lit("?B?") >> (*qi::char_("a-zA-Z0-9/=+")) [px::ref(qi::_b) <<= qi::_1][ qi::_c = px::bind(base64::decode, px::cref(qi::_b))] ) // "B" encoding
            |
            ( qi::lit("?Q?") >> (*(qi::char_-'?'))[ px::ref(qi::_b) <<= qi::_1][qi::_c = px::bind(qp::decode_header, qi::_b)] ) // "Q" encoding
       )  
    >> qi::lit("?=") )
//    [px::ref(LOG) << "<INPUT: \"" << qi::_b << "\", OUTPUT: \"" << qi::_c << "\".>\n"]
    [qi::_val += px::bind(to_utf8, qi::_a, qi::_c)] } // charset conversion


// all together
// Notes: "atom" has optional whitespaces at beginning and end, that shall _not_ belong to the atom.
// But when combined into "phrase"s, the ws between the words shall be kept. m(
// This changed grammar should handle this braindead requirements:
, encoded_words { encoded_word % qi::omit[cfws] }

// not used in atext
, aspecials { qi::char_("]()<>:;@\\,.\"[") }

// Text in quoted strings
, qtext { qi::char_ - qi::char_("\\\"") }
, qcontent { qpair | qtext }
, quoted_string { '"' >> *qcontent >> '"'}

, word { (quoted_string | encoded_words | atom_nows)
//    [px::ref(LOG) << "<<<WORD:“" << qi::_1 << "”.>>>"]
        [qi::_val += qi::_1]
       } // Note: putting "encoded_word" here is my own interpretation of RFC 2047
, phrase {-qi::omit[cfws] >> (word >> *( qi::hold[ocfws >> word] )) }
, unstructured { *(-fws >> (encoded_words | +(qi::char_ - qi::char_(" \t\r\n\f"))) ) }
{
    // intentionally left blank. :-)
}


bool match(const Rule& rule, sv content)
{
    sv::const_iterator begin = content.begin();
    bool b = qi::parse(begin, content.end(), rule);
    return  b && begin == content.end();
}

} // end of namespace pEpMIME
