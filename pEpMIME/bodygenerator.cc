#include "bodygenerator.hh"
#include "base64.hh"
#include "attachment.hh"
#include <set>


namespace pEpMIME
{

using namespace std::string_literals;


std::string generate_delimiter(unsigned long long counter)
{
    char buf[32];
    snprintf(buf, 31, "=pEp=%llx=", counter); // this delimiter cannot occur in base64- nor qp-encoded MIME leaves.
    return buf;
}

bool contains_delimiter(sv haystack, sv delimiter_base)
{
    const std::string delim = "\r\n--"s + delimiter_base;
    return haystack.find(delim) != sv::npos;
}


std::string create_delimiter(const std::vector<Attachment>& a)
{
    unsigned long long counter=0;
    std::string delimiter = generate_delimiter(counter);
    while( std::any_of(a.begin(), a.end(),
                        [&delimiter](const Attachment& att)
                        {
                            return att.need_te==false && contains_delimiter( att.data, delimiter);
                        }
                      )
         )
    {
        ++counter;
        delimiter = generate_delimiter(counter);
    }
    
    return delimiter;
}


std::string longmsg_mimetype(const message* msg)
{
    const auto longmsg_format = stringpair_list_find(msg->opt_fields, Pseudo_Header_Format.data());
    const auto longmsg_delsp  = stringpair_list_find(msg->opt_fields, Pseudo_Header_Delsp.data());
    
    return "text/plain"s
        + (longmsg_format ? "; format="s + longmsg_format->value->value : std::string())
        + (longmsg_delsp  ? "; delsp="s  + longmsg_delsp->value->value  : std::string())
        ;
}


void generate_body(std::string& smsg, sv mime_type, sv body)
{
    smsg += "Content-Type: "s + mime_type + "; charset=UTF-8;\r\n"s;
    
    if(need_transport_encoding(body)==false)
    {
        smsg += "\r\n"; // end of header section
        smsg += body;
    }else{
        smsg += "Content-Transfer-Encoding: base64\r\n"
                "\r\n"; // end of header section
        base64::encode(smsg, body, 78, "\r\n");
    }
}


void generate_ma_body(std::string& smsg, sv plain_mimetype, sv plain, sv html)
{
    const bool encode_plain = need_transport_encoding(plain);
    const bool encode_html  = need_transport_encoding(html);
    
    unsigned long long counter=0;
    std::string delimiter = generate_delimiter(counter);
    while( (!encode_plain && contains_delimiter(plain,delimiter) )
        || (!encode_html  && contains_delimiter(html ,delimiter) )
         )
    {
        ++counter;
        delimiter = generate_delimiter(counter);
    }
    
    smsg += "Content-Type: multipart/alternative; boundary=\"" + delimiter + "\";\r\n"
        "\r\n"; // end of header section
    
    smsg += "--" + delimiter + "\r\n";
    generate_body(smsg, plain_mimetype, plain);
    smsg += "--" + delimiter + "\r\n";
    generate_body(smsg, "text/html", html);
    smsg += "--" + delimiter + "--\r\n";
}


void generate_mm_body(std::string& smsg, sv mime_type, sv body, const std::vector<Attachment>& a)
{
    std::vector<Attachment> a2{a};
    a2.emplace_back(body, mime_type);
    
    const std::string delimiter = create_delimiter(a2);
    
    smsg += "Content-Type: multipart/mixed; boundary=\"" + delimiter + "\";\r\n"
        "\r\n"; // end of header section
    
    if(mime_type.size())
    {
        smsg += "--" + delimiter + "\r\n";
        generate_body(smsg, mime_type, body);
    }
    
    generate_attachments(smsg, a, delimiter);
}


// complex MIME structures, depending on "det"
// see: https://dev.pep.foundation/libpEpMIME
void generate_complex_body(std::string& smsg, unsigned det, const message* msg, const std::vector<Attachment>& a)
{
    const std::string longmsg_mimetype = pEpMIME::longmsg_mimetype(msg);

    std::vector<Attachment> a2{a};
    if(msg->longmsg)
        a2.emplace_back(msg->longmsg, longmsg_mimetype);
    
    if(msg->longmsg_formatted)
        a2.emplace_back(msg->longmsg_formatted, "text/html");
    
    // basic delimiter:
    const std::string delimiter = create_delimiter(a2) + "/" + std::to_string(det) + "/";
    
    switch(det)
    {
        case 6: smsg += "Content-Type: multipart/related; boundary=\"" + delimiter + "\";\r\n"
                "\r\n" // end of header section
                "--" + delimiter + "\r\n";
                generate_body(smsg, "text/html", msg->longmsg_formatted);
                generate_attachments(smsg, a, delimiter);
                break;
        case 7:
            { // m/a{ text/plain, m/rel{ text/html, att } }
                const std::string delimiter_A = delimiter + "A=";
                smsg += "Content-Type: multipart/alternative; boundary=\"" + delimiter_A + "\";\r\n"
                "\r\n"
                "--" + delimiter_A + "\r\n";
                generate_body(smsg, longmsg_mimetype, msg->longmsg);
                smsg += "--" + delimiter_A + "\r\n";
                const std::string delimiter_R = delimiter + "R=";
                smsg += "Content-Type: multipart/related; boundary=\"" + delimiter_R + "\";\r\n"
                "\r\n"
                    "--" + delimiter_R + "\r\n";
                    generate_body(smsg, "text/html", msg->longmsg_formatted);
                    generate_attachments(smsg, a, delimiter_R);
                smsg += "--" + delimiter_A + "--\r\n";
                break;
            }
        case 11:
            { // m/mix{ m/a{ text/plain, text/html}, att }
                const std::string delimiter_M = delimiter + "M=";
                const std::string delimiter_A = delimiter + "A=";
                smsg += "Content-Type: multipart/mixed; boundary=\"" + delimiter_M + "\";\r\n"
                "\r\n"
                "--" + delimiter_M + "\r\n";
                smsg += "Content-Type: multipart/alternative; boundary=\"" + delimiter_A + "\";\r\n"
                "\r\n"
                    "--" + delimiter_A + "\r\n";
                    generate_body(smsg, longmsg_mimetype, msg->longmsg);
                    smsg += "--" + delimiter_A + "\r\n";
                    generate_body(smsg, "text/html", msg->longmsg_formatted);
                    smsg += "--" + delimiter_A + "--\r\n"
                    "\r\n";
                generate_attachments(smsg, a, delimiter_M);
                break;
            }
        case 14:
            { // m/mix{ m/rel{ html, inline_att}, att }
                const std::string delimiter_M = delimiter + "M=";
                const std::string delimiter_R = delimiter + "R=";
                smsg += "Content-Type: multipart/mixed; boundary=\"" + delimiter_M + "\";\r\n"
                "\r\n"
                "--" + delimiter_M + "\r\n";
                    smsg += "Content-Type: multipart/related; boundary=\"" + delimiter_R + "\";\r\n"
                    "\r\n"
                    "--" + delimiter_R + "\r\n";
                    generate_body(smsg, "text/html", msg->longmsg_formatted);
                    generate_attachments(smsg, a, delimiter_R, &is_inline );
                    // closing of delimiter_R is done in generate_attachments()
                generate_attachments(smsg, a, delimiter_M, &is_not_inline );
                break;
            }
        case 15: // all doodads, bells and whistles
            { // m/mix { m/a{ text, m/rel{ html, inline } }, att }
                const std::string delimiter_M = delimiter + "M=";
                const std::string delimiter_A = delimiter + "A=";
                const std::string delimiter_R = delimiter + "R=";
                smsg += "Content-Type: multipart/mixed; boundary=\"" + delimiter_M + "\";\r\n"
                "\r\n"
                "--" + delimiter_M + "\r\n";
                smsg += "Content-Type: multipart/alternative; boundary=\"" + delimiter_A + "\";\r\n"
                "\r\n"
                    "--" + delimiter_A + "\r\n";
                    generate_body(smsg, longmsg_mimetype, msg->longmsg);
                    smsg += "--" + delimiter_A + "\r\n"
                    "Content-Type: multipart/related; boundary=\"" + delimiter_R + "\";\r\n"
                    "\r\n"
                        "--" + delimiter_R + "\r\n";
                        generate_body(smsg, "text/html", msg->longmsg_formatted);
                        generate_attachments(smsg, a, delimiter_R, &is_inline );
                        // closing of delimiter_R is done in generate_attachments()
                    smsg += "--" + delimiter_A + "--\r\n";
                generate_attachments(smsg, a, delimiter_M, &is_not_inline);
                break;

            }
        default:
            throw std::logic_error( "Generate_complex_body() with det=" + std::to_string(det) + " is iffy." );
    }
}


} // end of namespace pEpMIME
