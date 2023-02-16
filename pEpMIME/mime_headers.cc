// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "mime_headers.hh"
#include "rules.hh"
#include "base64.hxx"
#include "quoted_printable.hxx"
#include "string_case.hh"
#include "nfc.hh"
#include "to_utf8.hh"
#include "../src/pEp_string.h"

#include <boost/spirit/include/qi.hpp>
#include <boost/spirit/include/phoenix.hpp>
#include <boost/fusion/include/adapt_struct.hpp>


namespace qi = boost::spirit::qi;
namespace px = boost::phoenix;

using qi::_val;
using qi::_1;

namespace pEpMIME
{
    struct Rfc2231ParamName
    {
        std::string name;
        int count = -1;
        bool ext_value = false; // extended value:  charset'language'encoded_value
    };
    
    struct Rfc2231ParamValue
    {
        std::string charset;
        // language is ignored
        std::string value;
    };

}

    BOOST_FUSION_ADAPT_STRUCT(
        pEpMIME::ContentType,
        (std::string, type)
        (std::string, subtype)
        (std::vector<pEpMIME::NameValue>, tparams)
    )

    BOOST_FUSION_ADAPT_STRUCT(
        pEpMIME::ContentDisposition,
        (content_disposition_type, dispo_type)
        (std::vector<pEpMIME::NameValue>, dparams)
    )

/*
    BOOST_FUSION_ADAPT_STRUCT(
        Rfc2231ParamName,
        (std::string, name)
        (unsigned, count)
        (bool, with_charset)
    )
*/

// that boost::fusion magic seems to work only in the actual TU
// so it has to be defined here, instead of at the end of pEpMIME_internal.cc  *sigh*
BOOST_FUSION_ADAPT_STRUCT(
    pEpMIME::NameValue,
    (std::string, name)
    (std::string, value)
)


namespace pEpMIME
{

void ContentType::tolower()
{
    ascii_tolower(type);
    ascii_tolower(subtype);
}

BasicRules br;

// Tokens from RFC 2045
Rule token = +( br.vchar - qi::char_("]()<>@,;:\\\"/?=["));

TRule<NameValue> parameter = token >> '=' >> (token | br.quoted_string);
TRule<ContentType> content_type = token >> '/' >> token >> *( qi::omit[*br.cfws] >> -qi::lit(';') >> qi::omit[*br.cfws] >> parameter);

const qi::symbols<char, content_disposition_type> disposition_type(
        std::vector<sv>{"attachment", "inline"},
        std::vector<content_disposition_type>{ PEP_CONTENT_DISP_ATTACHMENT, PEP_CONTENT_DISP_INLINE}, "disposition_type"
        );

TRule<ContentDisposition> content_disposition = disposition_type >> *( qi::omit[*br.cfws] >> ';' >> qi::omit[*br.cfws] >> parameter);


qi::uint_parser<unsigned char, 16,2,2> hex_octet;

TRule<char> ext_octet = qi::lit('%') >> hex_octet;
TRule<char> attrib_char = qi::ascii::print - qi::char_("]*'%()<>@,:\\\"/?=[");

TRule<Rfc2231ParamName> param_name = 
           (+(qi::char_ - '*')) [ &(_val)->*&Rfc2231ParamName::name <<= _1 ]
        >> -(qi::lit('*') >> qi::uint_[ &(_val)->*&Rfc2231ParamName::count = _1] )
        >> -(qi::lit('*')[ &(_val)->*&Rfc2231ParamName::ext_value = true] );


TRule<Rfc2231ParamValue> param_value =
    -qi::hold[
    (+qi::char_("A-Za-z0-9_./-"))[ &(_val)->*&Rfc2231ParamValue::charset <<= _1 ]
    >> '\''
    >> qi::omit[ *(qi::char_ - '\'') ] // language is ignored
    >> '\''
     ]  // charset & language is optional and normally only present in the 1st part
    >> ( +(ext_octet | attrib_char))[ &(_val)->*&Rfc2231ParamValue::value <<= _1 ];


static std::string convert(std::string& charset, sv input)
{
    Rfc2231ParamValue pv;
    sv::const_iterator begin = input.begin();
    if(qi::parse(begin, input.end(), param_value, pv))
    {
        if(pv.charset.size())
        {
            charset = pv.charset;
        }
        return to_utf8(charset, pv.value);
    }
    return to_utf8(charset, input);
}

// unwrap multiline header params according to RFC 2231
static void unwrap(std::vector<NameValue>& params)
{
    std::vector<NameValue> new_params;
    std::string ml_name, ml_value; // multiline parameters
    std::string charset = "UTF-8";
    int old_count = -1;
    for(auto& p : params)
    {
        LOG << "UW: " << p << " : ";
        Rfc2231ParamName pn;
        sv pname{ p.name };
        sv::const_iterator begin = pname.cbegin();
        if(qi::parse(begin, pname.cend(), param_name, pn))
        {
            ascii_tolower(pn.name);
            LOG << " RFC2231. ext_value=" << pn.ext_value << ", count=" << pn.count << ".\n";
            const std::string& value = pn.ext_value ? convert(charset, p.value ) : p.value;
            switch(pn.count)
            {
                case -1 : // has charset but no multi-line value
                    new_params.emplace_back( pn.name, value );
                    break;
                case 0 : // start of a multi-line value
                    if(!ml_name.empty())
                    {
                        new_params.emplace_back( ml_name, ml_value);
                    }
                    ml_name = pn.name;
                    ml_value = value;
                    old_count = 0;
                    break;
                default:
                    if(pn.name == ml_name && pn.count == old_count+1)
                    {
                        ml_value += value;
                        old_count = pn.count;
                    }else{
                        // non-contiguous counter -> discard it.
                        LOG << "\tNONCONTIGUOUS COUNTER!!!\n";
                    }
                    break;
            }
        }else{
            if(!ml_name.empty())
            {
                new_params.emplace_back( ml_name, ml_value);
                ml_name.clear(); ml_value.clear();
            }
            // "legacy" parameter:
            LOG << " LEGACY PARAM.\n";
            new_params.emplace_back( std::move(p) );
        }
    }

    if(!ml_name.empty())
    {
        new_params.emplace_back( ml_name, ml_value);
        ml_name.clear(); ml_value.clear();
    }

    LOG << "UW: params.size()=" << params.size() << ", new_params.size()=" << new_params.size() << ". SWAP!\n";
    params.swap(new_params);
}


std::ostream& operator<<(std::ostream& o, const ContentType& ct)
{
    return o << "CT:{" << ct.type << "/" << ct.subtype << ". params=" << ct.tparams << " } ";
}


std::ostream& operator<<(std::ostream& o, const ContentDisposition& cd)
{
    return o << "CD:{" << cd.dispo_type << ". params=" << cd.dparams << " } ";
}


std::ostream& operator<<(std::ostream& o, const MimeHeaders& mh)
{
    return o << "MH { " << static_cast<const ContentType&>(mh) << "\n"
        "\t " << static_cast<const ContentDisposition&>(mh) << "\n"
        "\t transfer_encoding: " << mh.transfer_encoding << "\n"
        "}";
}

// for "7bit", "8bit" or "binary"
static char* identity_decode(const BodyLines& bl, size_t& output_size)
{
	const sv body = combineLines(bl);
	output_size = body.size();
	return new_string(body.data(), body.size());
}


static char* base64_decode(const BodyLines& bl, size_t& output_size)
{
	size_t out_size = 0;
	for(const auto& line : bl)
	{
	    LOG << "BASE64_D: “" << line << "”\n";
		out_size += (line.size()+3)/4 * 3;
	}
	
	const sv body = combineLines(bl);
	
	char* out_string = new_string(nullptr, out_size);
	char* out_begin = out_string;
	char* out_end = out_string + out_size;
	
	base64::decode_iter( body.begin(), body.end(), out_begin, out_end);
	output_size = out_begin - out_string;
	LOG << "BASE64_DECODE: " << bl.size() << " lines, " << body.size() << " raw octets decoded into " << output_size << " octets. (" << out_size << " expected.)\n" 
	    "\tBody: “" << body << "”\n";
	return out_string;
}


static char* qp_decode(const BodyLines& bl, size_t& output_size)
{
	const sv body = combineLines(bl);
	
	char* out_string = new_string(nullptr, body.size());
	char* out_begin = out_string;
	char* out_end = out_string + body.size();
	
	qp::decode_iter( body.begin(), body.end(), out_begin, out_end);
	output_size = out_begin - out_string;
	return out_string;
}


MimeHeaders::Decoder getDecoder(sv transfer_encoding)
{
    if(transfer_encoding == "base64")
    {
        return &base64_decode;
    }else if(transfer_encoding == "quoted-printable")
    {
        return &qp_decode;
    }
    
    return &identity_decode;
}


ContentType::ContentType(sv header_line)
{
    auto begin = header_line.cbegin();
    const bool okay = qi::parse(begin, header_line.cend(), content_type, *this);
    if(!okay)
    {
        LOG << "Cannot parse \"" + std::string{header_line} + "\" as ContentType.\n";
    }
    LOG << "<<< CT raw: " << *this << ">>>\n";
    unwrap(tparams);
    this->sanitize();
    LOG << "<<< CT san: " << *this << ">>>\n";

}

ContentDisposition::ContentDisposition(sv header_line)
{
    auto begin = header_line.cbegin();
    const bool okay = qi::parse(begin, header_line.cend(), content_disposition, *this);
    if(!okay)
    {
        LOG << "Cannot parse \"" + std::string{header_line} + "\" as ContentDisposition.\n";
    }
    LOG << "<<< CD raw: " << *this << ">>>\n";
    unwrap(dparams);
    LOG << "<<< CD uw: " << *this << ">>>\n";
}


MimeHeaders::MimeHeaders(const HeaderSection& headers)
: ContentType{ header_value(headers, "content-type") }
, ContentDisposition{ header_value(headers, "content-disposition" ) }
, transfer_encoding{ header_value(headers, "content-transfer-encoding") }
, decoder{ getDecoder( transfer_encoding ) }
{
}

} // end of namespace pEpMIME
