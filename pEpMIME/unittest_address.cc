// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "parse_address.hh"
#include "../src/pEpEngine.h"
#include <time.h>

#include <gtest/gtest.h>

namespace
{

struct TestEntry
{
	std::string s;
	std::string displayname;
	std::string address;
};

std::ostream& operator<<(std::ostream& o, const TestEntry& t)
{
	return o << "\"" << t.s << "\" -> Name=\"" << t.displayname << "\", Address=<" << t.address << ">  ";
}

const std::vector<TestEntry> testValues =
	{
		{"Alice <alice@pep.example>", "Alice", "alice@pep.example"},
		{"Alice Wonder <alice@pep.example>", "Alice Wonder", "alice@pep.example"},
		{"bob@pep.example", "", "bob@pep.example" },
		{"<bob@pep.example>", "", "bob@pep.example" },
		{"=?UTF-8?B?TcO2bGxlciDDnGJlcg==?= <moeller@pep-test.ch>", "Möller Über", "moeller@pep-test.ch"},
		{"=?iso-8859-1?Q?'M=FFrthe_=C4=DFink'?= <myrthe@pep.lol>", "'Mÿrthe Äßink'", "myrthe@pep.lol" },
		{"A1 A2 \"<Q3>\" \"<Q4>\"\"<Q5>\" =?ISO-8859-1?Q?En=E71?= =?ISO-8859-1?Q?En=E72?= A8 <atom-test@pep.lol>",
			"A1 A2 <Q3> <Q4> <Q5> Enç1Enç2 A8", "atom-test@pep.lol" },
		{"\"John Doe\" <\"john doe\"@pep.lol>", "John Doe", "john doe@pep.lol" },
	};

} // end of anonymous namespace


class AddressParserTest : public ::testing::TestWithParam<TestEntry>
{
	// intentionally left blank
};

INSTANTIATE_TEST_CASE_P(AddressParserTestInstance, AddressParserTest, testing::ValuesIn(testValues) );

TEST_P( AddressParserTest, Meh )
{
	const auto& v = GetParam();
	pEp_identity* id = pEpMIME::parse_address( v.s );

	ASSERT_NE( id , nullptr );
	EXPECT_EQ( id->address , v.address );
	EXPECT_EQ( id->username , v.displayname );
	free_identity(id);
}
