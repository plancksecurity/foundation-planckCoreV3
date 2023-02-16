// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <gtest/gtest.h>

#include "to_utf8.hh"
#include <vector>


namespace {


const char nullo[4] = {0,0,0,0};

const std::vector<std::string> testValuesIdentical =
	{
		{ "" },
		{ std::string(nullo, nullo+1)  },  // Yeah, 1 NUL byte
		{ std::string(nullo, nullo+4)  },  // Yeah, 4 NUL bytes
		{ "\taeiouAEIU~+-&\\ =?:\n\f</>\r" },
	};
}


class ToUtf8Test : public ::testing::TestWithParam<std::string>
{
	// intentionally left blank for now.
};

INSTANTIATE_TEST_CASE_P(ToUtf8TestInstance, ToUtf8Test, testing::ValuesIn(testValuesIdentical) );

TEST_P( ToUtf8Test, Meh )
{
	const auto& v = GetParam();
	EXPECT_EQ( v, to_utf8("UTF-8", v) );
	EXPECT_EQ( v, to_utf8("utf-8", v) );
	EXPECT_EQ( v, to_utf8("ISO-8859-1", v) );
	EXPECT_EQ( v, to_utf8("iso-8859-1", v) );
}

TEST( ToUtf8, Latin1 )
{
	EXPECT_EQ( to_utf8("ISO-8859-1", "\x84\xdc" "bergr\xf6\xdf" "en\xe4" "nderung\x93: 10\x80!"), "„Übergrößenänderung“: 10€!" );
	EXPECT_EQ( to_utf8("UTF-8", "„Übergrößenänderung“: 10€!"), "„Übergrößenänderung“: 10€!" );
}

TEST( ToUtf8, Latin9 )
{
	EXPECT_EQ( to_utf8("ISO-8859-15", "\xdc" "bergr\xf6\xdf" "en\xe4nderung: 10\xa4!"), "Übergrößenänderung: 10\xe2\x82\xac!" );
	std::string latin9, utf8;
	for(unsigned u=0; u<277; ++u)
	{
		latin9 += "\xb0\xa4\xbe"; // degree, euro, capital Y with diaeresis: °€Ÿ
		utf8 += "\xc2\xb0" "\xe2\x82\xac" "\xc5\xb8";
		EXPECT_EQ( to_utf8("ISO-8859-15", latin9), utf8 );
	}
}
