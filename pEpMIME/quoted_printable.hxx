// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "quoted_printable.hh"
#include <stdint.h>
#include <stdexcept>

namespace pEpMIME
{
namespace qp
{

    struct UnexpectedEnd {};
    struct IllegalHexSequence
    {
        IllegalHexSequence(char h, char l) : high(h), low(l) {}
        char high, low;
    };

    constexpr const int8_t __ = -1; // invalid char -> exception!

    extern const int8_t values[256];

    inline
    unsigned from_hex(char high, char low)
    {
        const int h2 = values[(unsigned char)high];
        const int l2 = values[(unsigned char)low];
        
        if(h2<0 || l2<0)
        {
            throw IllegalHexSequence{high,low};
        }
        
        return h2*16u + l2;
    }

    // use with potentially "infinite" output containers, e.g. together with back_insert_iterator<>
    struct InfinityIterator {};
    static InfinityIterator infinity_end{};
    
    template<class OutIter>
    inline
    bool operator==(OutIter out, InfinityIterator ii)
    {
        return false;
    }


template<class Iter>
int fetch(Iter& curr, Iter end)
{
    if(curr == end)
        return -1;
    
    const int ret = *curr;
    ++curr;
    return ret;
}


template<class OutIter, class OutIter2>
void copy_out(OutIter& out, OutIter2 out_end, char c)
{
    if(out == out_end)
    {
        throw std::runtime_error("Output buffer for QP-decoding is too small.");
    }
    
    *out = c;
    ++out;
}


template<class InIter, class OutIter, class OutIter2>
void decode_iter(InIter begin, InIter end, OutIter& out, OutIter2 out_end)
{
    InIter curr = begin;
    while(curr != end)
    {
        const char ch = fetch(curr, end);
        if(ch=='=')
        {
            const int first = fetch(curr, end);
            const int second = fetch(curr, end);
                
            if(first == '\r' && second == '\n') // soft line break
            {
                continue; // Soft Line Break: just absorb and go on.
            }
            try{
                copy_out(out, out_end, char(from_hex((char)first, (char)second)) );
            }catch(const IllegalHexSequence& e)
            {
                copy_out(out, out_end, '=');
                if(first>=0)  copy_out(out, out_end, first);
                if(second>=0) copy_out(out, out_end, second);
            }
        }else{
            copy_out(out, out_end, ch );
        }
    }
}


} // end of namespace pEpMIME::qp
} // end of namespace pEpMIME
