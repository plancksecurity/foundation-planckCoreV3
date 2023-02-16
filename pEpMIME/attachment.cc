#include "attachment.hh"
#include "pEpMIME_internal.hh"
#include "base64.hh"

#include <cstdio> // for snprintf()
#include <boost/algorithm/string/predicate.hpp>


namespace
{
	static const int8_t __ = 0;
	static const int8_t OK = 1;
	const int8_t allowed[256] = {
			//   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0x00 .. 0x0F
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0x10 .. 0x1F
			__, __, __, __, __, __, __, __, __, __, __, OK, __, OK, OK, __,  // 0x20 .. 0x2F   + - .
			OK, OK, OK, OK, OK, OK, OK, OK, OK, OK, __, __, __, __, __, __,  // 0x30 .. 0x3F   
			__, OK, OK, OK, OK, OK, OK, OK, OK, OK, OK, OK, OK, OK, OK, OK,  // 0x40 .. 0x4F
			OK, OK, OK, OK, OK, OK, OK, OK, OK, OK, OK, __, __, __, __, OK,  // 0x50 .. 0x5F   _
			__, OK, OK, OK, OK, OK, OK, OK, OK, OK, OK, OK, OK, OK, OK, OK,  // 0x60 .. 0x6F
			OK, OK, OK, OK, OK, OK, OK, OK, OK, OK, OK, OK, OK, OK, OK, __,  // 0x70 .. 0x7F
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0x80 .. 0x8F
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0x90 .. 0x9F
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0xA0 .. 0xAF
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0xB0 .. 0xBF
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0xC0 .. 0xCF
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0xD0 .. 0xDF
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0xE0 .. 0xEF
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0xF0 .. 0xFF
		};

    void percent_escape(std::string& out, unsigned char u)
    {
        char buf[8];
        std::snprintf(buf, 7, "%%" "%02hhx", u);
        out.append(buf, 3);
    }

    void percent_encode(std::string& out, sv s)
    {
        for(char c : s)
        {
            const uint8_t u = uint8_t(c);
            if( allowed[u] )
            {
                out += c;
            }else{
                percent_escape(out, u);
            }
        }
    }

} // end of anonymous namespace


namespace pEpMIME
{

void Attachment::write_mime_headers(std::string& out) const
{
    out += "Content-Type: ";
    out += mime_type;
    out += ";\r\n"
         "Content-Disposition: ";
    out += (dtype==PEP_CONTENT_DISP_INLINE ? "inline;\r\n" : "attachment;\r\n");
    
    if(filename.empty())
        return;
    
    // Nota bene: Don't support overlong Content-IDs because the RFCs don't allow line splitting here.
    if(boost::algorithm::starts_with(filename, "cid://"))
    {
        out += "Content-ID: <" + filename.substr(6) + ">\r\n";
    }else if(filename.size()<19)
    {
        out += " filename*=utf-8''";
        percent_encode(out, filename);
        out += "\r\n";
    }else{
        unsigned part = 0;
        for(unsigned ofs=0; ofs<filename.size(); ofs += 18, ++part)
        {
            out += " filename*";
            out += std::to_string(part);
            out += "*=utf-8''";
            percent_encode(out, filename.substr(ofs, 18));
            out += "\r\n";
        }
    }
}


SAttachments parse_attachments(const bloblist_t* b, bool has_pEp_msg_attachment)
{
    unsigned nr_in_bloblist = 0;
    SAttachments ret;
    while(b)
    {
        ret.emplace_back(b, nr_in_bloblist, has_pEp_msg_attachment);
        b = b->next;
        ++nr_in_bloblist;
    }
    return ret;
}


bool is_inline(const bloblist_t* b)
{
    return b->filename && boost::algorithm::starts_with(b->filename, "cid://");
}


// body needs transport encoding if it not "NETASCII with max. 78 chars per line".
bool need_transport_encoding(const sv body)
{
    unsigned line_length = 0u;
    unsigned state = 0u;
    
    for(char b : body)
    {
        const unsigned char u = b;
        if(u>126)
            return true;
        
        switch(u)
        {
            case '\r' : if(state==0)
                        {
                            state='\r';
                            break;
                        }else{
                            return true;
                        }
            case '\n' : if(state=='\r')
                        {
                            line_length=state=0; break;
                        }else{
                            return true;
                        }
            default: {
                        if(u<' ' && u!='\t') // control characters except TAB
                            return true;
                        
                        if(state!=0 || ++line_length > 78)
                            return true;
                     }
        }
    }
    return false;
}


void generate_attachments(std::string& out, const SAttachments& att, sv delimiter, bool(*filter)(const Attachment&))
{
    for(const auto& q : att)
    {
        if(filter(q)==true)
        {
            out += "--";
            out += delimiter;
            out += "\r\n";
            q.write_mime_headers(out);
            if(q.need_te)
            {
                out += "Content-Transfer-Encoding: base64\r\n"
                        "\r\n";
                base64::encode(out, q.data, 78, "\r\n");
            }else{
                out += "\r\n";
                out += q.data;
                out += "\r\n";
            }
        }
    }
    
    out += "--" + delimiter + "--\r\n";
}


} // end of namespace pEpMIME
