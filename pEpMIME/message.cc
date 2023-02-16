// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "message.hh"
#include <algorithm>

#include <boost/fusion/include/adapt_struct.hpp>

namespace pEpMIME
{
    // -1 = continuation line
    // -2 = illegal line
    // >0 = position of COLON, if starts with printable ASCII. :-)
    int header_line_type(sv line)
    {
        if(line.empty())
            return -2;
        if(line[0] == ':')
            return -2;
        if(line[0] == ' ' || line[0] == '\t')
            return -1;
        if(line[0] < 33 || line[0] > 126)
            return -2;
        
        // okay, only printable ASCII characters without ':' are left.
        return line.find(':');
    }


Message::Message(const BodyLines& lines)
: headers{}
, mh{headers}
{
    int headersize = -1;
    for(unsigned u=0; u<lines.size(); ++u)
    {
        if(lines[u].empty())
        {
            headersize = u;
            break;
        }
    }
    
    if(headersize<0)
    {
        headersize = lines.size();
    }
    
    // collect and unfold the header lines
    NameValue nv;
    for(int i=0; i<headersize; ++i)
    {
        sv line = lines.at(i);
        const int lineType = header_line_type(line);
        LOG << "Line #" << i << ": \"" << line << "\". type=" << lineType << ". \n";
        switch(lineType)
        {
            case -2: // line is bogus. But be robust: just skip that line and hope for the best...
                //throw std::runtime_error("Cannot handle line \"" + std::string(line) + "\"");  return nullptr;  // TODO: C'mon, don't give up, yet! :-)
                break;
            case -1: nv.value += std::string(line);
                break;
            default: 
            {
                if(!nv.name.empty())
                {
                    headers.push_back(nv);
                }
                nv.name = ascii_tolower(line.substr(0, lineType));
                const unsigned firstBody = lineType + 1; // 1st index _after_ the ':'
                if(firstBody < line.size()) // there is something after the ':'
                {
                    const char firstBodyChar = line.at(firstBody);  // if SPACE or TAB char: chop this char, too. but only the 1st!
                    nv.value = std::string( line.substr( firstBody + ( (firstBodyChar==' '|| firstBodyChar=='\t') ? 1 : 0) ));
                }
            }
        }
    }
    
    if(!nv.name.empty())
    {
        headers.push_back(nv);
    }

    LOG << "Parsing result: " << headers.size() << " parsed header lines (from " << headersize << " original lines):\n";
    for(const auto& h : headers)
    {
        LOG << "“" << h.name << "” : “" << h.value << "”\n";
    }
    
    mh = MimeHeaders{headers};
    
    // copy the remaining lines into body
    if(unsigned(headersize) < lines.size())
    {
        body.insert(body.end(), lines.begin() + headersize + 1, lines.end() );  // +1 to skip the empty line between header and body, if any
    }
}


sv Message::boundary() const
{
    return header_value(mh.tparams, "boundary");
}


std::ostream& operator<<(std::ostream& o, const Message& m)
{
    o << "Message: " << m.headers.size() << " header lines:\n";
    for(const auto& h : m.headers)
    {
        o << "\t" << h << "\n";
    }
    
    o << "followed by " << m.body.size() << " body lines.\n";
    return o;
}


} // end of namespace pEpMIME
