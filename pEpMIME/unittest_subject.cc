// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "pEpMIME.hh"
#include "../src/message.h"
#include <time.h>

#include <gtest/gtest.h>

namespace
{

struct TestEntry
{
	std::string encoded;
	std::string decoded;
};

std::ostream& operator<<(std::ostream& o, const TestEntry& t)
{
	return o << " encoded=\"" << t.encoded << "\", decoded=\"" << t.decoded << "\" ";
}

const std::vector<TestEntry> testValues =
	{
		{"=?UTF-8?B?TcO2bGxlciDDnGJlcg==?=", "Möller Über"},
		{"=?UTF-8?Q?M=C3=B6ller_=C3=9Cber?=", "Möller Über"},
		{"=?UTF-8?Q?Hallo_Das_ist_nur_ein_Test_f=c3=bcr_eine_lange_Subject-Ze?=\r\n"
		" =?UTF-8?Q?ile=2c_die_umgebrochen_wird=2c_da_sie_eben_viel_zu_l=c3=a4nglich_?=\r\n"
		"  =?UTF-8?Q?geworden_ist=2e?=", 
		"Hallo Das ist nur ein Test für eine lange Subject-Ze"
		"ile, die umgebrochen wird, da sie eben viel zu länglich "
		"geworden ist."},
	};

} // end of anonymous namespace


class SubjectParserTest : public ::testing::TestWithParam<TestEntry>
{
	// intentionally left blank
};

INSTANTIATE_TEST_CASE_P(SubjectParserTestInstance, SubjectParserTest, testing::ValuesIn(testValues) );

TEST_P( SubjectParserTest, Meh )
{
	const auto& v = GetParam();
	const std::string mime_msg = 
		"Subject: " + v.encoded + "\r\n"
		"From: example@pep.lol\r\n"
		"\r\n"
		"Hallo Welt.\r\n"
		"\r\n";

	message* m = pEpMIME::parse_message( mime_msg.c_str(), mime_msg.size() );
	ASSERT_NE( m , nullptr );
	EXPECT_EQ( m->shortmsg , v.decoded );
	free_message(m);
}
