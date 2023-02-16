// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "bodyparser.hh"
#include "pEpMIME_internal.hh"
#include "mime_headers.hh"
#include "message.hh"
#include "rules.hh"
#include "base64.hxx"
#include "headerparser.hh" // for add_opt_field()
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


namespace pEpMIME
{

typedef std::vector<Message> MultipartMessage;

MultipartMessage parse_multipart(const BodyLines& body, const sv& boundary)
{
    bool is_last = false;
    qi::rule<const char*, qi::unused_type()> is_delimiter_parser = qi::lit("--") >> qi::lit(boundary.data())
        >> -qi::lit("--")[ px::ref(is_last) = true] >> qi::omit[*qi::char_(" \t")];

    MultipartMessage vm;
    bool after_preamble = false;
    BodyLines part;
    LOG << "Parse_Multipart: " << body.size() << " body lines. bounardy=“" << boundary << "”. \n";
    for(const auto& line : body)
    {
        is_last = false;
        auto begin = line.cbegin();
        const bool is_delimiter = qi::parse( begin, line.cend(), is_delimiter_parser );
        if(is_delimiter)
        {
            LOG << "\t Line “" << line << "” is " << (is_last ? "LAST ":"") << "delimiter!\n";
            if(after_preamble)
            {
                vm.emplace_back( part );
                part.clear();
            }else{
                after_preamble = true;
            }

            if(is_last == true)
            {
                break;
            }
        }else{
            if(after_preamble)
            {
                part.emplace_back(line);
            }
        }
    }
    
    return vm;
}


char* create_string(const BodyLines& body, const sv& charset, MimeHeaders::Decoder decoder)
{
    if(body.empty())
        return nullptr;

    size_t decoded_size = 0;
    char* decoded = decoder(body, decoded_size);
    
    LOG << "CREATE_STRING: " << body.size() << " body lines into " << decoded_size << " raw octets (charset=\"" << charset << "\")\n";
    
    if(charset=="UTF-8" || charset=="UTF8")
    {
        // Move all NUL bytes to the end where they don't hurt.
        std::remove(decoded, decoded + decoded_size, '\0' );
        return decoded; // fine. :-)
    }else{
        // Sigh, the hard way. At the moment with a lot of unecessary copying. :-/
        // Rule 1: Make it work. Profile. Make it fast. In this order.
        std::string converted = to_utf8((charset.empty() ? "us-ascii" : charset), sv(decoded, decoded_size) ); // 1st copy...
        
        // remove any NUL bytes
        converted.erase( std::remove(converted.begin(), converted.end(), '\0'), converted.end() );
        pEp_free(decoded);
        return new_string( converted.data(), converted.size() ); // copy again. :'-(
    }
}


void add_attachment(message* msg, const BodyLines& body, const MimeHeaders& mh)
{
    size_t decoded_size = 0;
    char* decoded = mh.decoder(body, decoded_size);
    sv filename = header_value(mh.dparams, "filename");
    LOG << "ATTACHMENT filename=“" << filename << "”\n";
    if(filename.empty()) // no "filename" field in Content-Disposition?
    {
        filename = header_value(mh.tparams, "name"); // legacy: use "name" field from Content-Type header
        LOG << "ATTACHMENT name=“" << filename << "”\n";
    }
    
    const std::string content_type = mh.mime_type();
    if( (msg->attachments==nullptr) && (content_type=="message/rfc822") ) // very special requirement. See MIME-12
    {
        const sv forwarded = header_value( mh.tparams, "forwarded");
        if(forwarded.size())
        {
            add_opt_field(msg, Pseudo_Header_Forwarded, forwarded);
        }
    }
    
    bloblist_t* bl = bloblist_add(msg->attachments, decoded, decoded_size, content_type.c_str(), (filename.empty()? nullptr : filename.data()) );
    if(msg->attachments==nullptr)
    {
        msg->attachments = bl;
    }
}


struct has_mimetype
{
    has_mimetype(const char* _mime_type)
    : mt(_mime_type)
    {}

    bool operator()(const Message& m) const
    {
        return m.mh.mime_type() == mt;
    }
    
    const char* mt;
};


void set_longmsg(message* msg, const MimeHeaders& mh, const BodyLines& body)
{
    const sv txt_charset = header_value( mh.tparams, "charset" );
    const sv format      = header_value( mh.tparams, "format");
    const sv delsp       = header_value( mh.tparams, "delsp");
    
    msg->longmsg = create_string(body, txt_charset, mh.decoder );
    if(format.size())
    {
        add_opt_field(msg, Pseudo_Header_Format, format);
    }
    if(delsp.size())
    {
        add_opt_field(msg, Pseudo_Header_Delsp, delsp);
    }
}


void handle_multipart(message* msg, const MimeHeaders& mh, const BodyLines& body, unsigned level = 1)
{
    const sv boundary = header_value(mh.tparams, "boundary");
    MultipartMessage mm = parse_multipart( body, boundary );
    LOG << "MULTIPART/" << mh.subtype << ": " << mm.size() << " parts. Boundary = “" << boundary << "” :\n";

    LOG << "MM.size=" << mm.size() << ", level=" << level << ":\n";
    for(const auto& m : mm)
    {
        LOG << "°°M: " << m << "\n";
    }
    
    // All "multipart" MimeTypes: handle as "multipart/mixed":
    for(const Message& m : mm)
    {
        if(m.mh.type == "multipart")
        {
            if(level < MaxMultipartNestingLevel)
            {
                handle_multipart(msg, m.mh, m.body, level+1);
            }else{
                add_attachment(msg, m.body, m.mh);
            }
            continue;
        }
    
        if(m.mh.dispo_type == PEP_CONTENT_DISP_INLINE)
        {
            const auto mime_type = m.mh.mime_type();
            if(mime_type=="text/plain" && msg->longmsg==nullptr)
            {
                // the first "text/plain" part is handeld specially:
                set_longmsg(msg, m.mh, m.body);
                continue;
            }else if(mime_type=="text/html" && msg->longmsg_formatted==nullptr)
            {
                // first inline "text/html" part goes to longmsg_formatted
                const sv mc_charset = header_value( m.mh.tparams, "charset" );
                msg->longmsg_formatted = create_string(m.body, mc_charset, m.mh.decoder );
                continue;
            }
        }
        
        add_attachment(msg, m.body, m.mh);
    }
}


void handle_mime(message* msg, const MimeHeaders& mh, const BodyLines& body)
{
    if(mh.type == "text")
    {
        const sv charset = header_value( mh.tparams, "charset" );
        LOG << "\t Content-Type: " << mh.mime_type() << ", mh: " << mh << "\n";
        if(mh.subtype == "plain" && msg->longmsg==nullptr)
        {
            // put it in msg->longmsg
            set_longmsg(msg, mh, body);
        }else if(mh.subtype=="html" && msg->longmsg_formatted==nullptr)
        {
            // put it in msg->longmsg_formatted
            msg->longmsg_formatted = create_string(body, charset, mh.decoder);
        }else{
            // add it as attachment
            add_attachment(msg, body, mh);
        }
    }else if(mh.type == "multipart")
    {
        handle_multipart(msg, mh, body, 1);
    }else if(mh.type == "message")
    {
        // TODO: What shall I do with this MimeType?
        add_attachment(msg, body, mh);
    }else{
        // all other MIME types
        add_attachment(msg, body, mh);
    }
}


// parses the header and fill the parts in msg
void parse_body(message* msg, const HeaderSection& headers, const BodyLines& body)
{
    LOG << "ParseBody: " << body.size() << " body lines.\n";
    
    // anything that might be a MIME mail I try to parse as a MIME mail:
    if( header_value(headers, "mime-version").size() || header_value(headers, "content-type").size() )
    {
        MimeHeaders mh(headers);
        handle_mime(msg, mh, body);
    }else{ // Non-MIME mail
        LOG << "<<< NO_MIME_MAIL >>> " << body.size() << " body lines.\n";
        sv combined_body = combineLines(body);
        if(isUtf8(combined_body.begin(), combined_body.end()) )
        {
            const std::string& nfc_string = toNFC( combined_body ); // FIXME: double copy! :-((
            msg->longmsg = new_string(nfc_string.c_str(), nfc_string.size());  // FIXME: 3rd copy! :-(((
        }else{
            char* pbody = msg->longmsg = new_string(combined_body.data(), combined_body.size());
            // no valid UTF-8? Hum, whatever it is, make it 7-bit ASCII for safety.
            std::for_each(pbody, pbody+combined_body.size(), [](char& c) { c &= 0x7f; } );
        }
    }
}


} // end of namespace pEpMIME
