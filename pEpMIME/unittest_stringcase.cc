// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <gtest/gtest.h>

#include "string_case.hh"
#include <set>
#include <vector>
#include <algorithm>

namespace
{
    struct TestEntry
    {
        std::string s;
        unsigned long long hash;
        
        TestEntry(const std::string& _s, unsigned long long _h) : s(_s), hash(_h) {}
    };

    bool operator<(const TestEntry& a, const TestEntry& b)
    {
        return a.hash < b.hash;
    }

    std::vector<TestEntry> test_values;
}


TEST( StringCaseTest, Meh )
{
    test_values.clear();
    test_values.reserve(129*128*128 + 0xFFFFFF + 2);
    test_values.emplace_back("", ""_case);
    char buf[32] = "";
    
    for(unsigned u=0; u<128; ++u)
    {
        buf[0] = u;
        const std::string s = std::string(buf, buf+1);
        test_values.emplace_back( s, case_hash(s) );
        for(unsigned v=0; v<128; ++v)
        {
            buf[1] = v;
            const std::string s = std::string(buf, buf+2);
            test_values.emplace_back( s, case_hash(s) );
            for(unsigned w=0; w<128; ++w)
            {
                buf[2] = w;
                const std::string s = std::string(buf, buf+3);
                test_values.emplace_back( s, case_hash(s) );
            }
        }
    }
    
    std::cout << "Added " << test_values.size() << " test values." << std::endl;
    
    EXPECT_EQ( test_values.size(), 1 + 128 + (128*128) + (128*128*128) );
    
    for(unsigned long long u=0; u<=0xFFFFF; ++u)
    {
        snprintf(buf,31, "_%07llx_", u*171 );
        std::string s = buf;
        test_values.emplace_back( s, case_hash(s) );
    }
    
    std::cout << "Sort " << test_values.size() << " test values." << std::endl;
    
    std::sort(test_values.begin(), test_values.end());
    std::cout << "Sort done." << std::endl;
    
    unsigned long long h = test_values[0].hash;
    for(unsigned u=1; u<test_values.size(); ++u)
    {
        const TestEntry& t = test_values[u];
//        std::cout << u << " h=" << h << ": s=\"" << t.s << "\"\n";
        ASSERT_NE(t.hash, h);
        h=t.hash;
    }
}


TEST( StringCaseTest, Collide )
{
    std::set<TestEntry> s;
    
}
