// This file is under GNU General Public License 3.0
// see LICENSE.txt

// Defines an operator""_case that allows string literals in case labels:
// ""_case generates a guaranteed unique hash for all ASCII strings up to 9 characters
// ""_lcase generates a guaranteed unique hash for all lowercase (or all uppercase) letter strings up to 12 characters
//
//  switch( case_hash(s) )
//  {
//     case "foo"_case : handle_foo(); break;
//     case "bar"_case : handle_bar(); break;
//  }
//

#ifndef PEP_MIME_STRING_CASE_HH
#define PEP_MIME_STRING_CASE_HH

#include <cstring>  // for strlen()

constexpr inline
unsigned long long frobbel(unsigned long long u)
{
	return (u*131) ^ (u>>51);
}

// for lowercase letters only:
constexpr inline
unsigned long long lfrobbel(unsigned long long u)
{
	return (u*29);
}


constexpr inline
unsigned long long case_hash(const char* begin, const char* end)
{
	return begin==end ? 0 : frobbel( ((unsigned char)(begin[0])+1) + frobbel(case_hash(begin+1, end)) );
}

constexpr inline
unsigned long long lcase_hash(const char* begin, const char* end)
{
	return begin==end ? 0 : lfrobbel( ((unsigned char)(begin[0])) + lfrobbel(lcase_hash(begin+1, end)) );
}

constexpr inline
unsigned long long operator"" _case (const char* s, size_t len)
{
	return case_hash(s, s+len);
}

constexpr inline
unsigned long long operator"" _lcase (const char* s, size_t len)
{
	return lcase_hash(s, s+len);
}


inline
unsigned long long case_hash( const char* zero_terminated_string )
{
	return case_hash( zero_terminated_string, zero_terminated_string + strlen(zero_terminated_string) );
}

inline
unsigned long long lcase_hash( const char* zero_terminated_string )
{
	return lcase_hash( zero_terminated_string, zero_terminated_string + strlen(zero_terminated_string) );
}

inline
unsigned long long case_hash( const std::string& s)
{
    return case_hash( s.data(), s.data()+s.size() );
}

inline
unsigned long long lcase_hash( const std::string& s)
{
    return lcase_hash( s.data(), s.data()+s.size() );
}

#endif // PEP_MIME_STRING_CASE_HH
