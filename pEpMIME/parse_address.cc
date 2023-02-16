// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "parse_address.hh"
#include "pEpMIME_internal.hh"
#include "nfc.hh"
#include "rules.hh"
#include <boost/spirit/include/qi.hpp>
#include <boost/spirit/include/phoenix.hpp>
#include <boost/fusion/include/adapt_struct.hpp>

// shortcuts
namespace qi = boost::spirit::qi;
namespace px = boost::phoenix;


struct Identity
{
    std::string name;
    std::string address;
};

BOOST_FUSION_ADAPT_STRUCT(
    Identity,
    (std::string, name)
    (std::string, address)
)

namespace {

using namespace pEpMIME;

struct AddressRules : public BasicRules
{
    AddressRules() : BasicRules() {}

// loosely integrates "obs-local-part" from RFC 5322:
// first parse as quoted_string, than as encoded_word. if both fails, it might be dot_atom_text:
// to handle obs-local-part these tokens can repeat.
const Rule local_part = +(quoted_string | encoded_word | dot_atom_text);
const Rule dtext      = qi::char_ - qi::char_("]\\[");
const Rule domain_lit = qi::char_('[') >> *(-fws >> dtext) >> -fws >> qi::char_(']');
const Rule domain     = dot_atom_text | domain_lit; // obs-domain is not supported.
const Rule addr_spec  = local_part >> qi::char_('@') >> domain;

const Rule angle_addr = qi::omit[-fws] >> '<' >> addr_spec >> '>' >> qi::omit[-fws];

const TRule<Identity> name_addr = -(phrase|+(qi::char_-qi::char_(" <,"))) >> angle_addr;
const TRule<Identity> mailbox = qi::hold[ name_addr ] | (qi::attr("") >> addr_spec);

const TRule<Identity> identity_parser = qi::omit[-fws] >> mailbox >> qi::omit[-fws] /* | group */; // Group? ewww... unsupported.

const TRule< std::vector<Identity> > identity_list_parser = identity_parser % ','; 
//(qi::lit(',')[
//	px::ref(LOG) << " {KOMMA} " ])
//	;
};

} // end of anonymous namespace


namespace pEpMIME
{

// parses the RFC 5322 address in 's'
pEp_identity* parse_address(sv s)
{
    AddressRules AR;
    
    Identity iden;
    sv::const_iterator begin = s.begin();
    bool okay = qi::parse(begin, s.end(), AR.identity_parser, iden );
    LOG << " \n p_a(): === Identity \"" << s << "\" is " << (okay?"okay":"NOT OKAY") << ". name=“" << iden.name << "”, addr=“" << iden.address << "”.  ";
    
    if(!okay)
    {
        LOG << "Cannot parse “" << s << "” as a valid address. Error at position " << (begin - s.begin()) << ": \"" << *begin << "\" ";
        return nullptr;
    }
    
    LOG << " ===\n";
    
    return new_identity(toNFC(iden.address).c_str(), nullptr, nullptr, toNFC(iden.name).c_str());
}


identity_list* parse_address_list(sv s)
{
    AddressRules AR;

    std::vector<Identity> vi;
    sv::const_iterator begin = s.begin();
    bool okay = qi::parse(begin, s.end(), AR.identity_list_parser, vi );
    
    if(!okay)
    {
        LOG << "Cannot parse “" << s << "” as a valid address list. Error at position " << (begin - s.begin()) << ": \"" << *begin << "\" ";
        return nullptr;
    }
    
    LOG << "ADDR_LIST: I found " << vi.size() << " elements in address list “" << s << "”  \n";

    if(vi.empty())
        return nullptr;
    
    identity_list* iden_list = new_identity_list( nullptr );
    identity_list* iter = iden_list;
    for(const auto& i : vi)
    {
        pEp_identity* iden = new_identity( toNFC(i.address).c_str(), nullptr, nullptr, toNFC(i.name).c_str());
        identity_list_add( iter, iden );
    }
    
    return iden_list;
}

} // end of namespace pEpMIME
