// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <gtest/gtest.h>

#include "pEpMIME.hh"
#include "quoted_printable.hh"
#include <vector>


namespace {

struct TestEntry
{
	std::string input;
	std::string qp;
};

typedef TestEntry TE;


std::ostream& operator<<(std::ostream& o, const TestEntry& tt)
{
	return o << "input=«" << tt.input << "», qp=" << tt.qp << ".  ";
}


const char nullo[4] = {0,0,0,0};

const std::vector<TestEntry> testValues =
	{
		{ ""         , ""           },  // always start with the simple case ;-)
		{ std::string(nullo, nullo+1), "=00"  },  // Yeah, 1 NUL byte
		{ std::string(nullo, nullo+2), "=00=00"  },  // Yeah, 2 NUL bytes
		{ std::string(nullo, nullo+3), "=00=00=00"  },  // Yeah, 3 NUL bytes
		{ std::string(nullo, nullo+4), "=00=00=00=00"  },  // Yeah, 4 NUL bytes
		{ "a"     , "a" },
		{ "ab"    , "ab" },
		{ "abc"   , "abc" },
		{ "abcd"  , "abcd" },
		{ "ab=cd"  , "ab=3Dcd" },
		
		{ "ö", "=C3=B6" },
		{ "öö", "=C3=B6=C3=B6" },
		{ ".€\n.", ".=E2=82=AC=0A." },
		// line length limit
		{ ".123456789.123456789.123456789.123456789.123456789.123456789.123456789.12345",
		  ".123456789.123456789.123456789.123456789.123456789.123456789.123456789.12345"
		},
		{ ".123456789.123456789.123456789.123456789.123456789.123456789.123456789.123456",
		  ".123456789.123456789.123456789.123456789.123456789.123456789.123456789.12345=\r\n6"
		},
		{ "°äöü°äöü°äöü°äöü",
		  "=C2=B0=C3=A4=C3=B6=C3=BC=C2=B0=C3=A4=C3=B6=C3=BC=C2=B0=C3=A4=C3=B6=C3=BC=C2=B0=\r\n=C3=A4=C3=B6=C3=BC"
		},

	};

} // end of anonymous namespace


class QPTest : public ::testing::TestWithParam<TestEntry>
{
	// intentionally left blank for now.
};

INSTANTIATE_TEST_CASE_P(QPTestInstance, QPTest, testing::ValuesIn(testValues) );

TEST_P( QPTest, Encode )
{
	const auto& v = GetParam();
	EXPECT_EQ( pEpMIME::qp::encode(v.input), v.qp );
	EXPECT_EQ( pEpMIME::qp::decode(v.qp), v.input );
}


////////////////////////////////////////////////////////////////////////////

const std::vector<TestEntry> testValuesHdr =
	{
		 // Nota Bene: NUL bytes in strings are stripped during parsing,
		 //            because the Engine is in C and cannot handle those strings!
		{ ""                         , "Subject: =?UTF-8?Q?" "?="   },  // always start with the simple case ;-)
		{ std::string(nullo, nullo+1), "Subject: =?UTF-8?Q?=00?="   },  // Yeah, 1 NUL byte
		{ std::string(nullo, nullo+2), "Subject: =?UTF-8?Q?=00=00?="  },  // Yeah, 2 NUL bytes
		{ std::string(nullo, nullo+3), "Subject: =?UTF-8?Q?=00=00=00?="  },  // Yeah, 3 NUL bytes
		{ std::string(nullo, nullo+4), "Subject: =?UTF-8?Q?=00=00=00=00?="  },  // Yeah, 4 NUL bytes
		{ "a"     , "Subject: =?UTF-8?Q?a?=" },
		{ "ab"    , "Subject: =?UTF-8?Q?ab?=" },
		{ "abc"   , "Subject: =?UTF-8?Q?abc?=" },
		{ "abcd"  , "Subject: =?UTF-8?Q?abcd?=" },
		{ "ab cd" , "Subject: =?UTF-8?Q?ab_cd?=" },
		{ "ab=cd" , "Subject: =?UTF-8?Q?ab=3Dcd?=" },

		// line length limit
		// .123456789.123456789.123456789.123456789.123456789.123456789.123456789.123456
		{                    ".123456789.123456789.123456789.123456789.123456789.12345",
		  "Subject: =?UTF-8?Q?.123456789.123456789.123456789.123456789.123456789.12345?="
		},
		{                    ".123456789.123456789.123456789.123456789.123456789.123456",
		  "Subject: =?UTF-8?Q?.123456789.123456789.123456789.123456789.123456789.12345?=\r\n"
		  " =?UTF-8?Q?6?="
		},
		{ "°äöü°äöü°äöü°äöü€€€€",
		  "Subject: =?UTF-8?Q?=C2=B0=C3=A4=C3=B6=C3=BC=C2=B0=C3=A4=C3=B6=C3=BC=C2=B0=C3?=\r\n"
		  " =?UTF-8?Q?=A4=C3=B6=C3=BC=C2=B0=C3=A4=C3=B6=C3=BC=E2=82=AC=E2=82=AC=E2=82=AC?=\r\n"
		  " =?UTF-8?Q?=E2=82=AC?="
		},
	};


class QPHeaderTest : public ::testing::TestWithParam<TestEntry>
{
    // intentionally left blank for now.
};

INSTANTIATE_TEST_CASE_P(QPHeaderTestInstance, QPHeaderTest, testing::ValuesIn(testValuesHdr) );

TEST_P( QPHeaderTest, Encode )
{
	const auto& v = GetParam();
	std::string e = pEpMIME::qp::encode_header("Subject", v.input, pEpMIME::qp::Text);
	EXPECT_EQ( e, v.qp );
	
	e += "\r\n\r\nTest.\r\n";
	
	message* msg = pEpMIME::parse_message( e.c_str(), e.size() );
	ASSERT_NE( msg , nullptr );
	
	std::string input_non0 = v.input;
	// NUL bytes confuse C code, especially the Engine.
	input_non0.erase( std::remove(input_non0.begin(), input_non0.end(), '\0'), input_non0.end() );
	
	EXPECT_EQ( msg->shortmsg, input_non0 );
	free_message(msg);
}

