// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "print_message.hh"
#include <iostream>
#include <sstream>


namespace pEpMIME
{

using namespace std::string_literals;

std::string out(char* s)
{
    if(s==nullptr)
    {
        return "(NULL)";
    }
    
    return '"' + std::string(s) + '"';
}


std::string out(pEp_identity* id)
{
	if(id==nullptr)
	{
		return "ID{0} ";
	}else{
		return "ID{ addr=" + out(id->address) + ", fpr=" + out(id->fpr) + ", name=" + out(id->username) + "} ";
	}
}


std::string out(identity_list* idl)
{
	if(idl==nullptr)
	{
		return "IDL[] ";
	}else{
		std::string ret = "IDL[";
		pEp_identity* id = idl->ident;
		ret += out(id);
		while(idl->next)
		{
			idl = idl->next;
			ret += ", ";
			ret += out(idl->ident);
		}
		return ret + ']';
	}
}


std::string out(stringlist_t* sl)
{
	if(sl==nullptr)
	{
		return "NULL ";
	}else{
		std::string ret = "SL[";
		char* s = sl->value;
		ret += out(s);
		while(sl->next)
		{
			sl = sl->next;
			ret += ", ";
			ret += out(sl->value);
		}
		return ret + ']';
	}
}


std::string out(stringpair_list_t* spl)
{
	if(spl==nullptr)
	{
		return "NULL ";
	}else{
		std::string ret = "SPL[";
		auto sp = spl->value;
		ret += "“"s + sp->key + "”:“"s + sp->value + "”";
		while(spl->next)
		{
			spl = spl->next;
			auto sp = spl->value;
			ret += ", “"s + sp->key + "”:“"s + sp->value + "”";
		}
		return ret + ']';
	}
}


std::string out(bloblist_t* bl)
{
	if(bl==nullptr)
		return "BL(NULL)";
	
	std::stringstream ss;
	ss << "BL:(" << bloblist_length(bl) << ")=[";
	while(bl)
	{
		ss << "\n\t{size=" << bl->size << ", mimetype=" << out(bl->mime_type) << ", filename=" << out(bl->filename) << "}";
		bl = bl->next;
	}
	ss << "]";
	return ss.str();
}


#define PRINT(member)  std::cerr << "\t" #member ": " << out(m->member) << "\n"

void print_message(message* m)
{
    if(!m)
    {
        std::cerr << "NULL message!\n";
        return;
    }
    
    PRINT(dir);
    PRINT(id);
    PRINT(shortmsg);
    PRINT(longmsg);

    PRINT(longmsg_formatted);

    PRINT(attachments);
    PRINT(rawmsg_ref);
    PRINT(rawmsg_size);
    PRINT(sent);
    PRINT(recv);
    PRINT(from);
    PRINT(to);
    PRINT(recv_by);

    PRINT(cc);
    PRINT(bcc);
    PRINT(reply_to);
    PRINT(in_reply_to);

    PRINT(refering_msg_ref);
    PRINT(references);
    PRINT(refered_by);

    PRINT(keywords);
    PRINT(comments);
    PRINT(opt_fields);
    PRINT(enc_format);
}

#undef PRINT

} // end of namespace pEpMIME
