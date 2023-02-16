// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "parse_timestamp.hh"
#include "../src/timestamp.h"
#include "../src/platform.h" // for timegm()
#include <time.h>

#include <gtest/gtest.h>

namespace std
{
	ostream& operator<<(ostream& o, struct tm const& t)
	{
		char buf[80];
		snprintf(buf, 79, "<%04d-%02d-%02d %02d:%02d:%02d wday=%d yday=%d isdst=%d>",
			t.tm_year+1900, t.tm_mon+1, t.tm_mday,
			t.tm_hour, t.tm_min, t.tm_sec,
			t.tm_wday, t.tm_yday, t.tm_isdst
			);
		return o << buf;
	}
}

namespace
{

struct TestEntry
{
	std::string s;
	int year, month, day, hour, minute, second;   // note: month=0..11!
	int64_t sse; // seconds since Epoch...
};

std::ostream& operator<<(std::ostream& o, const TestEntry& t)
{
	char buf[80];
	snprintf(buf, 79, "(“%s” => %04d-%02d-%02d %02d:%02d:%02d  sse=%lld>",
		t.s.c_str(),
		1900+t.year, 1+t.month, t.day,
		t.hour, t.minute, t.second,
		(long long)(t.sse)
		);
	return o << buf;
}

const std::vector<TestEntry> testValues =
	{
		{ "Sun, 24 Nov 2000 11:45:15 -0500", 100, 10, 24, 16, 45, 15,  975084315 },
		{ "Sat, 29 Feb 2016 11:23:45 +0000", 116,  1, 29, 11, 23, 45, 1456745025 },
		{ "Sat, 29 Feb 2016 11:23:45 +0200", 116,  1, 29,  9, 23, 45, 1456737825 },
		{ "Sun, 01 Mar 2016 13:23:45 +1400", 116,  1, 29, 23, 23, 45, 1456788225 },
		{ "Fri, 28 Feb 2016 13:23:45 -1200", 116,  1, 29,  1, 23, 45, 1456709025 },
		{ "Fri, 28 Feb 2016 18:23:45 -0800", 116,  1, 29,  2, 23, 45, 1456712625 },
		{ "Fri, 28 Feb 2016 18:23:45 PST"  , 116,  1, 29,  2, 23, 45, 1456712625 },
	};

} // end of anonymous namespace


class TimestampTest : public ::testing::TestWithParam<TestEntry>
{
	// intentionally left blank
};

INSTANTIATE_TEST_CASE_P(TimestampTestInstance, TimestampTest, testing::ValuesIn(testValues) );

TEST_P( TimestampTest, Meh )
{
	const auto& v = GetParam();
	timestamp* ts = pEpMIME::parse_timestamp( v.s );

	ASSERT_NE( ts , nullptr );
	EXPECT_EQ( ts->tm_year, v.year   );
	EXPECT_EQ( ts->tm_mon , v.month  );
	EXPECT_EQ( ts->tm_mday, v.day    );
	EXPECT_EQ( ts->tm_hour, v.hour   );
	EXPECT_EQ( ts->tm_min , v.minute );
	EXPECT_EQ( ts->tm_sec , v.second );
	
	const time_t t = timegm( ts );
	EXPECT_EQ( t, v.sse );
	
	free_timestamp(ts);
}
