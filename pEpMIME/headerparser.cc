// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "headerparser.hh"
#include "nfc.hh"
#include "parse_address.hh"
#include "parse_timestamp.hh"
#include "rules.hh"
#include "to_utf8.hh"

#include "../src/pEp_string.h"
#include "../src/stringlist.h"
#include <boost/spirit/include/qi_char.hpp>
#include <boost/spirit/include/qi.hpp>  // TODO: find a more specific #include to reduce compile time. qi_omit.hh does not work, yet.
#include <deque>
#include <map>
#include <initializer_list>

// shortcuts
namespace qi = boost::spirit::qi;

namespace pEpMIME
{

typedef std::vector<std::string> DS;

const Rule mchar = +(qi::char_ - qi::char_("<>\\()"));  // accept more char values than RFC requires.
const Rule message_id = qi::omit[ *qi::char_("\t\n\r ")] >> qi::lit('<') >> mchar >> qi::lit('>');
const qi::rule<sv::const_iterator, DS() > message_id_list = *message_id;


std::string robust_to_utf8(sv s)
{
    std::string ret;
    try{
        ret = toNFC(s);
    }catch(illegal_utf8& e)
    {
        ret = to_utf8("ISO-8859-1", s);
    }
    
    // NUL bytes confuse C code, especially the Engine.
    // MIME-15: remove all C0 control characters.
    ret.erase( std::remove_if(ret.begin(), ret.end(), [](char c){ return uint8_t(c) < ' ' || c=='\177'; } ), ret.end() );
    return ret;
}


void add_opt_field(message* msg, const sv& name, sv value)
{
    const std::string nfc_name  = robust_to_utf8(name);  // TODO: use views/ranges to avoid copying
    const std::string nfc_value = robust_to_utf8(value); // TODO: use views/ranges to avoid copying
    auto sp = new_stringpair( nfc_name.c_str(), nfc_value.c_str() );
    auto f = stringpair_list_add( msg->opt_fields, sp);
    
    // the function above has a strange semantic:
    // it adds the stringpair to the given list (if it is non-NULL) or returns it (if given list is NULL).
    if(f)
    {
        if(msg->opt_fields == nullptr) 
        {
            msg->opt_fields = f;
        }else{
            // do nothing. f is already added to the list. oO
        }
    }else{ // stringpair_list_add() fails for whatever reason: avoid memory leak
        free_stringpair(sp);
    }
}


stringlist_t* create_stringlist( const DS& v)
{
//    LOG << "CREATE_STRINGLIST with " << v.size() << " elements..." << std::endl;
    stringlist_t* sl = new_stringlist( nullptr );
    stringlist_t* s_iter = sl;
    for( const auto& s : v )
    {
        s_iter = stringlist_add( s_iter, s.c_str() );
    }
    return sl;
}


struct Discard : public HeaderBase
{
    Discard() : HeaderBase(sv{}) {}

    virtual void assign(message* msg, sv s) override
    {
        // Do nothing, intentionally. So this header is discarded.
    }
    
    virtual void output(std::string&, const message*) override
    {
       // do nothing.
    }
};

template<class TM>
struct OutputHeader : HeaderBase
{
    TM message::* member;
    void (*out_fn)(std::string&, const TM& data);
    
    OutputHeader(sv name, TM message::* m, void(*out)(std::string&, const TM&))
    : HeaderBase(name)
    , member{m}
    , out_fn{out}
    {}
    
    virtual void output(std::string& out, const message* msg) override
    {
        out_fn(out, msg->*member);
    }

};

// Header that assigns the result of a given function to the message data member
template<class TM>
struct SimpleHeader : public OutputHeader<TM>
{
    typedef OutputHeader<TM> Base;
    TM (*in_fn)(sv);
    
    SimpleHeader(sv name, TM message::* m, TM(*in)(sv), void(*out)(std::string&, const TM&))
    : Base(name, m, out)
    , in_fn{in}
    {}
    
    virtual void assign(message* msg, sv s) override
    {
        msg->*Base::member = (*in_fn)(s);
    }
    
};


// Parser that assigns the result of a qi::rule and a (conversion) function to a message data member
template<class TM, class TP>
struct RuleHeader : public OutputHeader<TM>
{
    typedef qi::rule<sv::const_iterator, TP()> rule_t;
    typedef OutputHeader<TM> Base;

    TM (*in_fn)(const TP&);
    const rule_t& rule;
    
    RuleHeader(sv name, TM message::* m, const rule_t& r, TM(*in)(const TP&), void(*out)(std::string&, const TM&) )
    : Base(name, m, out)
    , in_fn(in)
    , rule{r}
    {}
    
    virtual void assign(message* msg, sv s) override
    {
        sv ss(s);
        sv::const_iterator begin=ss.begin();
        TP t1;
//        LOG << "<TRY TO PARSE \"" << s << "\" as " << typeid(T1).name() << ">\n";
        if( qi::parse(begin, ss.end(), rule, t1) )
        {
//            LOG << "<ASSIGN OK>\n";
            msg->*Base::member = (*in_fn)(t1);
        }else{
//            LOG << "<ASSIGN NOT OKAY: begin='" << *begin << "'>\n";
        }
    }

};


void just_copy(std::string& out, const std::string& value)
{
    out += value;
}


// header known by RFC or convention but that are stored only in msg->opt_fields
struct AuxHeader : public HeaderBase
{
//    typedef qi::rule<sv::const_iterator, std::string()> rule_t;
    typedef void (*out_fn_t)(std::string&, const std::string& value);
    
    out_fn_t out_fn;

    AuxHeader(sv name, out_fn_t out = nullptr)
    : HeaderBase(name)
    , out_fn{out}
    {}
    
    virtual void assign(message* msg, sv s) override
    {
        add_opt_field(msg, HeaderBase::name(), s);
    }

    virtual void output(std::string& out, const message* msg) override
    {
        if(out_fn)
        {
            const std::string name_s { name() };
            auto spl = stringpair_list_find( msg->opt_fields, name_s.c_str() );
            if(spl)
            {
                out += name_s + ": ";
                out_fn(out, spl->value->value);
                out += "\r\n";
            }
        }
    }

};

// trampoline function templatebecause we have no template parameter type deduction for classes, until C++17. :-/
template<class TM>
std::pair<const std::string, HeaderBase*> P(sv name, TM message::* member, TM(*func)(sv))
{
    return std::make_pair(ascii_tolower(name), new SimpleHeader<TM>(name, member, func, nullptr));
}

template<class TM, class TP>
std::pair<const std::string, HeaderBase*> P(sv name, TM message::* member, const qi::rule<sv::const_iterator, TP()>& rule, TM (*func)(const TP&))
{
    return std::make_pair(ascii_tolower(name), new RuleHeader<TM, TP>(name, member, rule, func, nullptr));
}

std::pair<const std::string, HeaderBase*> PAUX( HeaderBase* hb)
{
    return std::make_pair(ascii_tolower(hb->name()), hb);
}



// make sure the C string is allocated on the correct heap, especially on MS Windows. *sigh*
char* copy_string(const std::string& s)
{
    LOG << "COPY_STRING: “" << s << "”.\n";
    const std::string nfc = robust_to_utf8(s); // TODO: use views/ranges to avoid copying
    return new_string(nfc.c_str(), nfc.size());
}


// access via function required, so the map itself is guaranteed to be initialized _after_ any
// static Rules in rules.cc, e.g. 'unstructured'.
HeadersMap& headersMap_internal()
{
    static BasicRules br;
    
    static HeadersMap hm =
    {
        P("Date",       &message::recv    ,             &parse_timestamp) ,
        P("Message-Id", &message::id      , message_id, &copy_string),
        P("Subject",    &message::shortmsg, br.unstructured , &copy_string),
        P("From",       &message::from,     &parse_address     ),
        P("To",         &message::to,       &parse_address_list),
        P("Cc",         &message::cc,       &parse_address_list),
        P("Bcc",        &message::bcc,      &parse_address_list),
        P("Reply-To",   &message::reply_to, &parse_address_list),
        
        P("In-Reply-To", &message::in_reply_to, message_id_list, &create_stringlist),
        P("References",  &message::references,  message_id_list, &create_stringlist),
        
        { "received",     new Discard}, // discard due to privacy reasons
        { "mime-version", new Discard}, // discard because unnecessary
        
        PAUX( new AuxHeader("Content-Type", nullptr) ),
        PAUX( new AuxHeader("Content-Disposition", nullptr) ),
        PAUX( new AuxHeader("Content-Transfer-Encoding", nullptr) ),
        
    };
    
    return hm;
}


// public API function: only access to "const" map
const HeadersMap& headersMap()
{
    return headersMap_internal();
}

// just for cleanup.
namespace {
	struct GlobalCleanup
	{
		GlobalCleanup() : hm{headersMap_internal()} {}
		
		~GlobalCleanup()
		{
			for(auto& e : hm) { delete e.second; e.second = nullptr; }
		}
		
		HeadersMap& hm;
	};

	GlobalCleanup gc;
}


// parses the header and fill the parts in msg
void parse_header(message* msg, const HeaderSection& header)
{
    if(msg==nullptr)
        throw std::logic_error("Null msg!?");
    
    for(const auto& h : header)
    {
        const std::string name_low = ascii_tolower(h.name);
        const auto hp = headersMap().find( name_low );
        if(hp == headersMap().end())
        {
            // unknown header with no special parser: just dump it in opt_fields
            add_opt_field(msg, h.name, h.value);
        }else{
            // do the "right thing" with this well-known header line:
            hp->second->assign(msg, h.value);
        }
    }
}

} // end of namespace pEpMIME
