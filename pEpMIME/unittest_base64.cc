// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <gtest/gtest.h>

#include "base64.hh"
#include <vector>


namespace {

struct TestEntry
{
	std::string input;
	std::string b64;
};

typedef TestEntry TE;


std::ostream& operator<<(std::ostream& o, const TestEntry& tt)
{
	return o << "input=«" << tt.input << "», base64=" << tt.b64 << ".  ";
}


const char nullo[4] = {0,0,0,0};

const std::vector<TestEntry> testValues =
	{
		{ ""         , ""           },  // always start with the simple case ;-)
		{ std::string(nullo, nullo+1), "AA=="  },  // Yeah, 1 NUL byte
		{ std::string(nullo, nullo+2), "AAA="  },  // Yeah, 2 NUL bytes
		{ std::string(nullo, nullo+3), "AAAA"  },  // Yeah, 3 NUL bytes
		{ std::string(nullo, nullo+4), "AAAAAA=="  },  // Yeah, 4 NUL bytes
		{ "a"     , "YQ==" },
		{ "ab"    , "YWI=" },
		{ "abc"   , "YWJj" },
		{ "abcd"  , "YWJjZA==" },
		{ "abcde" , "YWJjZGU=" },
		{ "abcdef", "YWJjZGVm" },
		
		{ "ö", "w7Y=" },
		{ "öö", "w7bDtg==" },
		{ "ööö", "w7bDtsO2"},
		{ "€€€", "4oKs4oKs4oKs" },

	};

}

class Base64Test : public ::testing::TestWithParam<TestEntry>
{
	// intentionally left blank for now.
};

INSTANTIATE_TEST_CASE_P(Base64TestInstance, Base64Test, testing::ValuesIn(testValues) );

TEST_P( Base64Test, Encode )
{
	const auto& v = GetParam();
	EXPECT_EQ( pEpMIME::base64::encode(v.input), v.b64 );
	EXPECT_EQ( pEpMIME::base64::decode(v.b64), v.input );
}


TEST( Base64DecodeTest, WhiteSpace )
{
    EXPECT_EQ( pEpMIME::base64::decode( "w7xiZXIgMTAg4oKsIQ==" ), "über 10 €!" );
    EXPECT_EQ( pEpMIME::base64::decode(
        "w7xiZXIgMT\r\n"
        "Ag4oKsIQ==\r\n" ), "über 10 €!" );
    
    const std::string bogus = 
       "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQAQMAAAAlPW0iAAAABlBMVEVmM5n///9dvR/iAAAA\r\n"
        "    H0lEQVQIHWP4Ic/wgJ3hADN\r\n"
        "DAyMIYQKIOFABUNkPeQC4LQeH3BOsvgAAAABJRU5ErkJggg==\r\n";
    const std::string deco = pEpMIME::base64::decode( bogus );
    EXPECT_EQ( deco.size() , 106 );
}

