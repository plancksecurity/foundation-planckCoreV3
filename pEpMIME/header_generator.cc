#include "header_generator.hh"
#include "headerparser.hh" // for access to HeadersMap headersMap
#include "quoted_printable.hh"
#include <boost/spirit/include/qi.hpp>

namespace pEpMIME
{

using namespace std::string_literals;

namespace
{
    using qp::HeaderType;

    typedef std::string (*TransportEncoder)(const Rule& rule, sv name, sv value, HeaderType type);

    std::string dont_encode(const Rule&, sv name, sv value, HeaderType type)
    {
        return name.empty() ? std::string(value) : (std::string(name) + ": " + value);
    }
    
    std::string just_fold(sv name, sv value, HeaderType type)
    {
        if((name.size() + value.size() + 2) < 76)
            return dont_encode(qi::char_ /* just a dummy */, name, value, type);
        
        std::string ret{name};
        ret += ':';
        size_t line_len  = ret.size();
        size_t value_pos = 0;
        while(value_pos<value.size())
        {
            const size_t next_ws = value.find(' ', value_pos);
            const sv     next_word = value.substr(value_pos, next_ws - value_pos);
            if(line_len + next_word.size() < 76)
            {
                ret += ' ';
                line_len += next_word.size() + 1;
            }else{
                ret += "\r\n ";
                line_len = 1;
                if(line_len + next_word.size() >76)
                {
                    // Oh noez, toooo long word, so folding is not enough! *sigh*
                    // -> QP-encoding can fold even within words. Ugly but better than exceed the line length limit.
                    return qp::encode_header(name, value, type);
                }
            }
            ret += next_word;
            value_pos = (next_ws == sv::npos ? next_ws : next_ws + 1); // +1 to skip the whitespace
        }
        
        return ret;
    }
    
    
    std::string encode_header_if_necessary(const Rule& rule, sv name, sv value, HeaderType type)
    {
        if(value.empty())
            return std::string();
        
        return match(rule, value) ? just_fold(name, value, type) : qp::encode_header(name, value, type);
    }
    
    std::string encode_local_part(sv local_part)
    {
        // create a "quoted-string" according to RFC 5322 sect. 
        std::string s;
        s.reserve(local_part.size() + 3);
        s += '"';
        for(char c:local_part)
        {
            switch(c)
            {
                case '\"' : s += "\\\""; break;
                case '\\' : s += "\\\\"; break;
                default   : s += c;
            }
        }
        s += '"';
        return s;
    }
    
//    static const TransportEncoder encoder[2] = { &dont_encode, &encode_header_if_necessary };
    
    static const std::string CRLF = "\r\n"s;
}


void generate(std::string& out, sv header_name, const pEp_identity* id)
{
    LOG << "GEN_ID: " << NN(id->username) << " | " << NN(id->address) << std::endl;
    static BasicRules br;
    
    out += exists(id->username) ? encode_header_if_necessary(br.phrase, header_name, id->username, qp::Word) + " " : std::string() ;
    
    if(!exists(id->address))
        return;
    
    out += '<';
    const sv address(id->address);
    const size_t last_at = address.rfind('@');
    const sv local_part = address.substr(0, last_at == sv::npos ? last_at : last_at-1);
    if( match(br.dot_atom_text, local_part) )
    {
        out += address;
    }else{
        out += encode_local_part(local_part);
        out += address.substr(last_at); // from the last '@' (including) to the end of address. :-)
    }
    out += '>';
}


void generate(std::string& out, sv header_name, const identity_list* il)
{
    LOG << "GEN_IDList: " << identity_list_length(il) << " entries. " << std::endl;
    
    if( identity_list_length(il) == 0)
        return;
    
    generate(out, header_name, il->ident);
    il = il->next;
    while(il)
    {
        out += ",\r\n\t";
        generate(out, sv{}, il->ident);
        il = il->next;
    }
}


void generate(std::string& out, const Rule& rule, sv header_name, const stringlist_t* sl)
{
    if( stringlist_length(sl) == 0)
        return;
    
    out += encode_header_if_necessary(rule, header_name, sl->value, qp::Word);
    sl = sl->next;
    while(sl)
    {
        out += ",\r\n\t" + encode_header_if_necessary(rule, "", sl->value, qp::Word);
        sl = sl->next;
    }
}


void generate_msgids(std::string& out, sv header_name, const stringlist_t* sl)
{
    if( stringlist_length(sl) == 0)
        return;
    
    out += header_name;
    out += ": <";
    out += sl->value;
    out += ">";
    sl = sl->next;
    while(sl)
    {
        out += std::string("\r\n\t<") + sl->value + ">";
        sl = sl->next;
    }
}



void generate_header(std::string& smsg, const message* msg)
{
    LOG << "GEN_HDR:" << std::endl;
    static BasicRules br;
    
    if(msg->id) smsg += "Message-ID: <"s + msg->id + ">\r\n";
    if(msg->shortmsg) smsg += encode_header_if_necessary(br.phrase, "Subject", msg->shortmsg, qp::Text) + CRLF;
    
    LOG << "\t smsg so far: " << smsg << std::endl;
    
    // FIXME: msg->sent , msg->received
    
    if(msg->from) { generate(smsg, "From", msg->from); smsg += CRLF; }
    if(msg->to)   { generate(smsg, "To"  , msg->to  ); smsg += CRLF; }
    if(msg->cc)   { generate(smsg, "Cc"  , msg->cc  ); smsg += CRLF; }
    if(msg->bcc)  { generate(smsg, "Bcc" , msg->bcc ); smsg += CRLF; }
    
    LOG << "\t smgs2 so far: " << smsg << std::endl;
    
    if(msg->recv_by)     { generate(smsg, "Received-By", msg->recv_by    ); smsg += CRLF; }
    if(msg->reply_to)    { generate(smsg, "Reply-To"   , msg->reply_to   ); smsg += CRLF; }
    if(msg->in_reply_to) { generate_msgids(smsg, "In-Reply-To", msg->in_reply_to); smsg += CRLF; }
    if(msg->references ) { generate_msgids(smsg, "References" , msg->references ); smsg += CRLF; }
    if(msg->keywords)    { generate(smsg, br.phrase, "Keywords"  , msg->keywords); smsg += CRLF; }
    
    const stringpair_list_t* spl = msg->opt_fields;
    LOG << "GEN_HDR: " << stringpair_list_length( spl ) << " opt_fields.\n";
    
    while(spl)
    {
        const char* const key = spl->value->key;
        
        // header keys starting with ':' are pseudo headers for pEp-internal use only.
        // Don't emit them in the MIME output
        if(key[0]==':')
        {
            goto skip_header;
        }else
        {
            const std::string key_low = ascii_tolower(key);
            auto q = headersMap().find(key_low);
            if(q == headersMap().end())
            {
                // unknown header: only encode if contained control characters or non-ASCII characters
                LOG << "\t UNKNWON HDR: " << spl->value->key << " :: " << spl->value->value << " <<< \n";
                smsg += encode_header_if_necessary( *(br.vchar | br.ws), spl->value->key, spl->value->value, qp::Text);
                smsg += CRLF;
            }else{
                LOG << "\t KNWON HDR: " << spl->value->key << " :: low_key: " << q->first << "  name(): " << q->second->name() << " <<< \n";
                q->second->output(smsg, msg);
            }
        }
        
skip_header:
        spl = spl->next;
    }
}

} // end of namespace pEpMIME

