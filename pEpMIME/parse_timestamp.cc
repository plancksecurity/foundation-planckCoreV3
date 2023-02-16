// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "parse_timestamp.hh"
#include "pEpMIME_internal.hh"
#include <map>
#include <boost/spirit/include/qi.hpp>
#include <boost/spirit/include/phoenix.hpp>
#include <initializer_list>

#include "../src/timestamp.h"
#include "../src/platform.h" // for timegm()


// shortcuts
namespace qi = boost::spirit::qi;
namespace px = boost::phoenix;

namespace std
{

ostream& operator<<(ostream& o, tm t)
{
    char buffer[64] = "";
    strftime(buffer, 63, "%F %T", &t);
    o << "Timestamp [" << buffer << "]";
    return o;
}

}

namespace {

#define COPY(member) do{ if(src.member) dst.member = src.member; }while(0)
timestamp& cpy_ts(timestamp& dst, const timestamp& src)
{
    COPY(tm_sec);
    COPY(tm_min);
    COPY(tm_hour);
    COPY(tm_mday);
    COPY(tm_mon);
    COPY(tm_year);
    COPY(tm_wday);
    COPY(tm_yday);
    COPY(tm_isdst);
//    COPY(tm_gmtoff);
    return dst;
}
#undef COPY

template<class T, class... LOCALS>
using Parser = qi::rule<sv::const_iterator, T(), qi::locals<LOCALS...> >;

typedef qi::rule<sv::const_iterator, std::string()> Rule;
typedef qi::rule<sv::const_iterator> Literal;
typedef qi::rule<sv::const_iterator, int()> IntParser;

// whitespace :-)
extern const Rule comment;
const Rule vchar = qi::char_("!-~"); // U+0021 ... U+007E - visible ASCII chars.

const Rule ws = qi::char_('\t') | ' ';
const Rule qp = qi::lit('\\') >> (vchar | ws); // quoted pair

// Comments
const Rule ctext = qi::omit[ qi::char_ - qi::char_("()\\") ];
const Rule ccontent = ctext | qp | comment.alias();
const Rule comment = qi::lit('(') >> *(ws | ccontent) >> -ws >> qi::lit(')');
const Rule cfws = qi::omit[ ( +(+ws >> comment >> +ws)) | ws ];

typedef std::vector<std::string> VS;
typedef std::vector<int> VI;


// Date and Time
const qi::symbols<char, int> sign(
        VS{"+", "-"},
        VI{ +1,  -1}
        );

const qi::symbols<char, int> day_name(
        VS{"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"},
        VI{1,2,3,4,5,6,0}, "day_of_week"
        );

const qi::symbols<char, int> month_name(
        VS{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"},
        VI{0,1,2,3,4,5,6,7,8,9,10,11}, "month"
        );

const qi::symbols<char, int> obs_zone( // TODO: add the other "military timezones", too?
        VS{"UT", "GMT",  "EST", "EDT", "CST", "CDT",  "MST", "MDT", "PST", "PDT", "Z"},
        VI{ +0 , +0   ,  -5*60, -4*60, -6*60, -5*60,  -7*60, -6*60, -8*60, -7*60, +0},
        "timezone"
        );

auto ows = qi::omit[ws];

const IntParser digit1_2 = qi::int_parser<unsigned, 10, 1,2>();
const IntParser digit2 = qi::int_parser<unsigned, 10, 2,2>();
const IntParser digit4 = qi::int_parser<unsigned, 10, 4,4>();

using qi::_val;
using qi::_1;

#define CPY px::bind(&cpy_ts, _val, _1)

const Parser<int, int> zone = qi::omit[-ws]
    >> ((sign[qi::_a=_1] >> digit2[_val = _1*60] >> digit2[_val +=_1] )[_val *= qi::_a]
    || obs_zone[_val=_1]);

const Parser<timestamp> time_of_day =   digit2[(&_val)->*&timestamp::tm_hour = _1]
            >>   -ows >> ':' >> -ows >> digit2[(&_val)->*&timestamp::tm_min  = _1]
            >> -(-ows >> ':' >> -ows >> digit2[(&_val)->*&timestamp::tm_sec  = _1] );

const Parser<timestamp> time_parser = time_of_day[ _val = _1] >> zone[ (&_val)->*&timestamp::tm_sec -= _1 * 60];

const IntParser year = (digit4[_val=_1]
                      | digit2[ qi::_val = px::if_else(qi::_1 < 50 , 2000+qi::_1 , 1900 + qi::_1) ]) /* [px::ref(LOG) << "@Y@:" << qi::_val] */ ;

const Parser<timestamp> date_parser = -ows >> digit1_2  [(&_val)->*&timestamp::tm_mday = _1]
                                    >> ows >> month_name[(&_val)->*&timestamp::tm_mon  = _1]
                                    >> ows >> year      [(&_val)->*&timestamp::tm_year = _1 - 1900];

const Parser<timestamp> date_time = (day_name[(&_val)->*&timestamp::tm_wday = _1] >> ',') 
    >> date_parser[ CPY ] >> +ows 
    >> time_parser[ CPY ] >> -cfws;

} // end of anonymous namespace


namespace pEpMIME
{

    using namespace std::string_literals;

    void test_parse_timezone()
    {
        const std::vector<sv> t = {
            "+0000", "+0100", "-0100", "+1130", "-1230"
        };
        
        for(const auto& s : t)
        {
            sv::const_iterator begin = s.begin();
            int i = -42;
            bool okay = qi::parse(begin, s.end(), zone, i  );
            LOG << " \n ===Zone: \"" << s << "\" -> " << i << " === (" << okay << ") ===\n";
        }
    }
    
    template<class T>
    void test_parse(const std::vector<sv>& data, const Parser<T>& parser, const char* name)
    {
        for(const auto& s : data)
        {
            sv::const_iterator begin = s.begin();
            T t{};
            bool okay = qi::parse(begin, s.end(), parser, t  );
            LOG << "\t=== " << name << ": \"" << s << "\" -> " << t << " is " << (okay?"okay":"NOT OKAY");
            if(!okay)
            {
                LOG << ". Error at position " << (begin - s.begin()) << ": \"" << *begin << "\" ";
            }
            LOG << " ===\n";
        }
    }


// parses the RFC 822 timestamp in 's'
timestamp* parse_timestamp(sv s)
{
    timestamp* ts = new_timestamp(0);
    
/***
    test_parse<int>( std::vector<std::string>{ "Mon", "Tue", "Wed", "Thu" }, day_name, "DayOfWeek" );
    test_parse<timestamp>( std::vector<std::string>
        { "11 Oct 1992", "19 Dec 49", "3 Sep 50", "24 Apr 01" }, date_parser, "Date" );

    test_parse<timestamp>( std::vector<std::string>
        { "11:22:33 +0000", "11:22:33 +0200" }, time_parser,  "Time" );

    test_parse<timestamp>( std::vector<std::string>
        { "Thu, 20 Oct 1992 11:22:33 +0000", 
          "Sun, 20 Oct 1992 11:45:15 -0500" }, date_time,  "DateTime" );
***/
    std::cerr << " \n === TimeStamp \"" << s << "\" to parse...\n";
    sv::const_iterator begin = s.begin();
    bool okay = qi::parse(begin, s.end(), date_time, *ts );
    LOG << " \n === TimeStamp \"" << s << "\" is " << (okay?"okay":"NOT OKAY");
    
    if(!okay)
    {
        LOG << ". Error at position " << (begin - s.begin()) << ": \"" << *begin << "\" ";
    }
    
    LOG << " ===\n";
    
    // normalize values:
    timegm(ts);
    
    return ts;
}

} // end of namespace pEpMIME
