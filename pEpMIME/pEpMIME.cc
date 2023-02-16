// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "pEpMIME.hh"
#include "pEpMIME_internal.hh"
#include "attachment.hh"
#include "message.hh"
#include "headerparser.hh"
#include "bodyparser.hh"
#include "header_generator.hh"
#include "bodygenerator.hh"
#include <initializer_list>
#include <deque>
#include <ostream>
#include <iostream>

#include "../src/pEp_string.h"  // for new_string()

namespace pEpMIME
{
    namespace
    {
        template<class InputIt, class UnaryPredicate>
        InputIt find_if_iter(InputIt first, InputIt last, UnaryPredicate p)
        {
            for (; first != last; ++first)
            {
                if (p(first))  // note: the predicate got the iterator, not the dereferenced value!
                {
                    return first;
                }
            }
            return last;
        }
    
        // RFC-compliant "Internet Message Format"
        struct is_crlf
        {
            static constexpr int increment = 2;
            static bool pred(const char* c)
            {
                return ( c[0] == '\r' && c[1] == '\n');
            }
        };

        // bogus but common
        struct is_lf
        {
            static constexpr int increment = 1;
            static bool pred(const char* c)
            {
                return c[0] == '\n';
            }
        };

        // bogus and less common
        struct is_cr
        {
            static constexpr int increment = 1;
            static bool pred(const char* c)
            {
                return c[0] == '\r';
            }
        };

        // very bogus but last try to parse it
        struct is_cr_or_lf
        {
            static constexpr int increment = 1;
            static bool pred(const char* c)
            {
                return c[0] == '\n' || c[0] == '\r';
            }
        };


        std::ostream& operator<<(std::ostream& o, const std::deque<sv>& container)
        {
            o << container.size() << " elements" << (container.empty() ? "\n" : ":\n");
            for(const auto& e : container)
            {
                o << "\t“" << e.to_string() << "”" << std::endl;
            }
            return o;
        }

        // a shallow copy of pEpEngine's struct message with own opt_fields
        class MessageCopy
        {
        public:
            MessageCopy(const message* _msg_orig)
            : msg_orig(_msg_orig)
            , msg_copy(*msg_orig)
            {
                if(msg_orig->opt_fields)
                {
                    msg_copy.opt_fields = stringpair_list_dup(msg_orig->opt_fields);
                }
            }
            
            void add_header(sv key, sv value)
            {
                stringpair_t* sp = new_stringpair(key.data(), value.data());
                if(sp==nullptr)
                {
                    throw std::runtime_error("Out of memory. new_stringpair() in add_header() fails.");
                }
                
                auto success = stringpair_list_add(msg_copy.opt_fields, sp);
                if(!success)
                {
                    free_stringpair(sp);
                    throw std::runtime_error("Out of memory. stringpair_list_add() in add_header() fails.");
                }
                
                // there were no opt_fields, yet?  So set them to the "last" (and only) element:
                if(msg_copy.opt_fields == nullptr)
                {
                    msg_copy.opt_fields = success;
                }
            }
            
            // Neither copy nor move!
            MessageCopy(const MessageCopy&) = delete;
            MessageCopy(MessageCopy&&) = delete;
            
            ~MessageCopy()
            {
                free_stringpair_list(msg_copy.opt_fields);
                msg_copy.opt_fields = nullptr;
            }
            
            operator const message*  () const { return &msg_copy; }
            const message* operator->() const { return &msg_copy; }
        
        private:
            const message* msg_orig;
            message msg_copy;
        };

    } // end of anonymous namespace


template<class LineEnding>
message* parse_message2(const char* begin, const char* const end)
{
    int headersize = -1;
    std::deque<sv> lines;
    const char* p = begin;
    while(p != end)
    {
        const char* sol = p;
        const char* eol = find_if_iter(p, end, &LineEnding::pred);
        lines.push_back( sv(sol, eol-sol) );
        if(lines.back().empty() && headersize<0)
        {
            headersize = lines.size()-1;
        }
        p = (eol!=end) ? eol+LineEnding::increment : end;
    }
    
    if(headersize<0)
    {
        headersize = lines.size();
    }
    LOG << "Parsing result: " << headersize << " raw header lines, " << (lines.size()-headersize) << " body lines:\n" << lines;
    
    Message m{lines};
    LOG << "Message: header has " << m.headers.size() << " lines, MimeHeaders.mime_type=\"" << m.mh.mime_type() << "\", " << m.body.size() << " body lines.\n";
    if(m.headers.size()==0 || (m.headers.size()==1 && m.body.size()==0) )
    {
        // does not seem to be a correctly parsed MIME message. Maybe wrong line ending? Giving up here.
        return nullptr;
    }

    message* msg = new_message(PEP_dir_incoming);
    parse_header(msg, m.headers);
    parse_body(msg, m.headers, m.body);
    return msg;
}


message* parse_message(const char* mime_text, size_t length, bool* raise_attachment)
{
    const char* const end_text = mime_text + length;
    message* msg = parse_message2<is_crlf>(mime_text, end_text);
    
    if(!msg)
    {
        msg = parse_message2<is_lf>(mime_text, end_text);
    }
    
    if(!msg)
    {
        msg = parse_message2<is_cr>(mime_text, end_text);
    }
    
    if(!msg)
    {
        msg = parse_message2<is_cr_or_lf>(mime_text, end_text);
    }
    
    if(msg && raise_attachment)
    {
        stringpair_list_t* forwarded = stringpair_list_find(msg->opt_fields, pEpMIME::Pseudo_Header_Forwarded.data());
        *raise_attachment = (forwarded && forwarded->value && forwarded->value->value==std::string{"no"});
        
        // don't emit this pseudo header to clients.
        msg->opt_fields = stringpair_list_delete_by_key(msg->opt_fields, pEpMIME::Pseudo_Header_Forwarded.data());
    }
    
    return msg;
}


char* generate_message(const message* msg_orig, bool omit_fields, bool has_pEp_msg_attachment)
{
    if(msg_orig == nullptr)
        return nullptr;
    
    LOG << "GEN_MSG omit=" << omit_fields << ", has_pEp_msg_att=" << has_pEp_msg_attachment << std::endl;
    MessageCopy msg{msg_orig};
    
    if(has_pEp_msg_attachment)
    {
        msg.add_header(Pseudo_Header_Forwarded, "no");
    }
    
    const auto attachments = parse_attachments(msg->attachments, has_pEp_msg_attachment);
    const unsigned inline_attachments = std::count_if(
            attachments.cbegin(), attachments.cend(),
            [](const Attachment& a) { return a.is_inline(); }
        );
    
    
    const unsigned det =
            exists(msg->longmsg)
        + 2*exists(msg->longmsg_formatted)
        + 4*!!(inline_attachments) // has inline attachments?
        + 8*!!(attachments.size()-inline_attachments); // has non-inline attachments?

    std::string smsg;
    if(omit_fields == false)
    {
        generate_header(smsg, msg);
    }
    
    const std::string longmsg_mimetype = ::pEpMIME::longmsg_mimetype(msg);

    switch(det)
    {
        case  0 : generate_body(smsg, "text/plain"   , ""                     ); break; // empty text/plain body
        case  1 : generate_body(smsg, longmsg_mimetype , msg->longmsg         ); break;
        case  2 : generate_body(smsg, "text/html"    , msg->longmsg_formatted ); break;
        case  3 : generate_ma_body(smsg, longmsg_mimetype, msg->longmsg, msg->longmsg_formatted); break;
        
        case  4 : generate_mm_body(smsg, sv{}, sv{}                         , attachments); break;
        case  5 : generate_mm_body(smsg, longmsg_mimetype, msg->longmsg     , attachments); break;
        case  6 : generate_complex_body(smsg, det, msg, attachments); break; // FIXME!
        case  7 : generate_complex_body(smsg, det, msg, attachments); break; // FIXME!
        
        case  8 : generate_mm_body(smsg, sv{}, sv{}                         , attachments); break;
        case  9 : generate_mm_body(smsg, longmsg_mimetype, msg->longmsg     , attachments); break;
        case 10 : generate_mm_body(smsg, "text/html", msg->longmsg_formatted, attachments); break;
        case 11 : generate_complex_body(smsg, det, msg, attachments); break; // FIXME!
        
        case 12 : generate_mm_body(smsg, sv{}, sv{}                         , attachments); break;
        case 13 : generate_mm_body(smsg, longmsg_mimetype, msg->longmsg     , attachments); break;
        case 14 : generate_complex_body(smsg, det, msg, attachments); break; // FIXME!
        case 15 : generate_complex_body(smsg, det, msg, attachments); break; // FIXME!
        
        default:
            throw std::logic_error("Determinant ouf of range 0...15: det=" + std::to_string(det) );
    }
    
    return new_string( smsg.data(), smsg.size() ); // make a C-compatible copy allocated by the "right" allocator. *sigh*
}


} // end of namespace pEpMIME
