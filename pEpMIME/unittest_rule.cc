// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "rules.hh"
#include <gtest/gtest.h>
#include <boost/optional.hpp>
#include <boost/optional/optional_io.hpp>
#include <boost/spirit/include/qi.hpp>


namespace
{

typedef boost::optional<std::string> OptString;
using namespace pEpMIME;

using namespace std::string_literals;


const BasicRules br;


struct TE_Base
{
	TE_Base(const std::string& in, const OptString& res)
	: input{in}
	, result{res}
	{}

	virtual ~TE_Base() = default;
	virtual OptString parse(const std::string& input) const = 0;

	std::string input;
	OptString   result;
};

template<class R>
struct TestEntry : public TE_Base
{
	TestEntry(const std::string& input, const R& _rule, const OptString& result)
	: TE_Base{input, result}
	, rule{_rule}
	{}

	const R&    rule;
	
	virtual OptString parse(const std::string& input) const override
	{
		std::string output;
		sv svi{input};
		sv::const_iterator begin = svi.begin();
		const bool okay = qi::parse(begin, svi.end(), rule, output );
		
		return okay ? output : OptString{};
	}
};

template<class R>
TE_Base* TE(const std::string& input, const R& _rule, const OptString& result)
{
	return new TestEntry<R>(input, _rule, result);
}

std::ostream& operator<<(std::ostream& o, const TE_Base* t)
{
	return o << "\"" << t->input << "\" -> Result=" << (t->result ? ("“" + *(t->result) + "”") : "(NONE)") << "\"  ";
}

#define NONE OptString{}

std::vector<TE_Base*> testValues =
	{
		TE(""    , br.vchar, NONE ),
		TE(" "   , br.vchar, NONE ),
		TE("x"   , br.vchar, "x"s ),
		TE(""    , br.qpair, NONE ),
		TE("x"   , br.qpair, NONE ),
		TE("\\\"", br.qpair, "\""s ),
		TE("\\\\", br.qpair, "\\"s ),
		TE("\\Q" , br.qpair, "Q"s  ),
		TE(""    , br.fws  , NONE ),
		TE(" "   , br.fws  , " "s ),
		TE("   " , br.fws  , " "s ),
		TE("\r\n\t \n"  , br.fws, " "s ),
		TE(" x " , br.fws  , " "s ),
		TE("x  " , br.fws  , NONE ),
		
		TE("=?UTF-8?Q?Banane?=", br.encoded_word, "Banane"s ),
		TE("=?UTF-8?Q?=C3=84pfel?=", br.encoded_word, "Äpfel"s ),
		
		TE(""  , br.comment, NONE ),
		TE("\\", br.comment, NONE ),
		TE("()", br.comment, ""s ),
		TE("(a comment)" , br.comment, ""s ),
		TE("(invalid (x)", br.comment, NONE ),
		TE("(this is (a nested\") comment \\) )", br.comment, ""s),
		TE("(this is (a \"nested) comment \\( )", br.comment, ""s),
		
		TE("   (a (nested) comment in a comment)  ", br.cfws, " "s),
	};

} // end of anonymous namespace


class RuleTest : public ::testing::TestWithParam<TE_Base*>
{
public:
	static void TearDownTestCase()
	{
		std::cerr << "TEAR DOWN TEST SUITE.\n";
		for(auto& e : testValues)
		{
			delete e;
			e = nullptr;
		}
		testValues.clear();
	}
};

INSTANTIATE_TEST_CASE_P(RuleTestInstance, RuleTest, testing::ValuesIn(testValues) );

TEST_P( RuleTest, Meh )
{
	const auto& v = GetParam();
	const OptString result = v->parse( v->input );
	EXPECT_EQ( result , v->result );
}
