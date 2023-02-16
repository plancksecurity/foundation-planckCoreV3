#ifndef PEP_MIME_ATTACHMENT_HH
#define PEP_MIME_ATTACHMENT_HH

#include <vector>
#include "../src/bloblist.h"
#include "pEpMIME_internal.hh"

namespace pEpMIME
{
    // body needs transport encoding if it not "NETASCII with max. 78 chars per line".
    bool need_transport_encoding(const sv body);
    
    // true if b->filename starts with "cid://"
    bool is_inline(const bloblist_t* b);


    // refers to data in a bloblist_t. Does NOT any data!
    struct Attachment
    {
        explicit Attachment(const bloblist_t* b, unsigned nr_in_bloblist, bool has_pEp_msg_attachment)
        : data{b->size ? sv{b->value, b->size} : sv{}}
        , mime_type{exists(b->mime_type) ? b->mime_type : "application/octet-stream"}
        , filename{exists(b->filename) ? b->filename : sv{}}
        , dtype{b->disposition}
        , need_te{need_transport_encoding(data)}
        {
            if(::pEpMIME::is_inline(b))
            {
                dtype = PEP_CONTENT_DISP_INLINE;
            }
            
            if((mime_type=="message/rfc822") && (nr_in_bloblist==0) && has_pEp_msg_attachment)
            {
                mime_type += "; forwarded=\"no\"";
            }
        }
        
        Attachment(sv _data, sv _mime_type)
        : data{_data}
        , mime_type{_mime_type.size() ? _mime_type : "application/octet-stream"}
        , filename{}
        , dtype{ PEP_CONTENT_DISP_OTHER }
        , need_te{ need_transport_encoding(data) }
        { }
        
        
        void write_mime_headers(std::string& out) const;
        
        bool is_inline() const
        {
            return dtype == PEP_CONTENT_DISP_INLINE;
        }
        
        sv data;
        std::string mime_type;
        sv filename;
        content_disposition_type dtype;
        bool need_te; // need transport encoding
    };
    
    typedef std::vector<Attachment> SAttachments;
    
    SAttachments parse_attachments(const bloblist_t* att, bool has_pEp_msg_attachment);
    
    inline
    bool all(const Attachment&) { return true; }
    
    inline
    bool is_inline(const Attachment& att) { return att.is_inline(); }

    inline
    bool is_not_inline(const Attachment& att) { return att.is_inline() == false; }
    
    // serialize all attachments, with the given delimiter
    // NOTA BENE: It closes this multipart/* subtree by adding the proper final delimiter.
    void generate_attachments(std::string& out, const SAttachments& att, sv delimiter, bool(*filter)(const Attachment&) = all);

}

#endif // PEP_MIME_ATTACHMENT_HH
