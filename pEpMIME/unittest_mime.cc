// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "pEpMIME.hh"
#include "pEpMIME_internal.hh" // for Pseudo_Header_Delsp
#include "headerparser.hh"
#include "mime_headers.hh"
#include "print_message.hh"
#include "base64.hh"
//#include "../src/slurp.hh"
#include <iostream>
#include <gtest/gtest.h>
#include <boost/algorithm/string/replace.hpp>

using namespace std::string_literals;

namespace
{
	static const char* mail1_eml =
		"Return-Path: <alice@pep-project.org>\r\n"
		"X-Original-To: alice@pep-project.org\r\n"
		"Delivered-To: alice@pep-project.org\r\n"
		"Received: from localhost (localhost [127.0.0.1])\r\n"
		"\tby dragon.pibit.ch (Postfix) with ESMTP id B84AF171C06F\r\n"
		"\tfor <alice@pep-project.org>; Wed, 16 Jan 2019 16:29:39 +0100 (CET)\r\n"
		"Received: from dragon.pibit.ch ([127.0.0.1])\r\n"
		"\tby localhost (dragon.pibit.ch [127.0.0.1]) (amavisd-new, port 10024)\r\n"
		"\twith ESMTP id q0wZqHMoT1gS for <alice@pep-project.org>;\r\n"
		"\tWed, 16 Jan 2019 16:29:37 +0100 (CET)\r\n"
		"Received: from Alice-PC.local (unknown [192.168.128.20])\r\n"
		"\tby dragon.pibit.ch (Postfix) with ESMTPSA id 563DD171C06A\r\n"
		"\tfor <alice@pep-project.org>; Wed, 16 Jan 2019 16:29:37 +0100 (CET)\r\n"
		"To: Bob <bob@pep-project.org>\r\n"
		"From: Alice <alice@pep-project.org>\r\n"
		"Cc: Carol Couscous  <carol.couscous+private@pep.lol>, Dave Doe (III) \r\n"
		"  Dexter <dave-dexter@pep.ooo>, dodo@pep.lol, \"Eve @ Evil\" <eve@evil.lol>\r\n"
		"  Mallory =?UTF-8?B?TcO2bGxlcg==?= (private) <\"mallory @ moeller\"@sinister.aq>\r\n"
		"Subject: =?UTF-8?B?UsO4ZGdyw7hkIG1lZCBmbMO4ZGU=?=\r\n"
		"Openpgp: preference=signencrypt\r\n"
		"Organization: =?UTF-8?B?8J+Ukg==?=\r\n"
		"Message-ID: <65a2df2c-ddc8-0875-a142-21acf62ed467@pep-project.org>\r\n"
		"References: <msg-alfa@pep.id> <msg-bravo@pep.aq> <lol-123456789@intern.sc.ful-lol.example>\r\n"
		"  <msg-charlie@pep.aq>\r\n"
		"In-Reply-To: <msg-reply-0815@pep.aq>\r\n"
		"Date: Wed, 16 Jan 2019 16:29:30 +0100\r\n"
		"User-Agent: B\r\n"
		"MIME-Version: 1.0\r\n"
		"Content-Type: multipart/mixed;\r\n"
		" boundary=\"==pEp_01==\"\r\n"
		"\r\n"
		"This is a Multipart MIME message.\r\n"
		"--==pEp_01==\r\n"
		"Content-Type: multipart/alternative; boundary=\"==pEp_02==\";\r\n"
		" protected-headers=\"v1\"\r\n"
		"\r\n"
			"--==pEp_02==\r\n"
			"Content-Type: text/plain; charset=\"utf-8\"\r\n"
			"Content-Language: en-US\r\n"
			"Content-Transfer-Encoding: quoted-printable\r\n"
			"\r\n"
			"R=C3=B8dgr=C3=B8d med fl=C3=B8de?\r\n"
			"\r\n"
			"--==pEp_02==\r\n"
			"Content-Type: multipart/related; boundary=\"==pEp_LoL==\";\r\n"
			"\r\n"
				"--==pEp_LoL==\r\n"
				"Content-Type: text/html; charset=\"ISO-8859-1\";\r\n"
				"Content-Transfer-Encoding: quoted-printable\r\n"
				"\r\n"
				"<html lang=3D=22de=22><body>=DCbergr=F6=DFen=E4nderung: 1=\r\n"
				"0=80.</body></html>\r\n"
				"\r\n"
				"--==pEp_LoL==\r\n"
				"Content-Type: image/png; name=\"rebeccapurple-circle.png\"\r\n"
				"Content-Language: en-US\r\n"
				"Content-ID: <rebeccapurple-circle-fb25fbb3-fd0b-46af-b567-7d1aa5725c49@pep.lol>\r\n"
				"Content-Transfer-Encoding: base64\r\n"
				"Content-Disposition: inline;\r\n"
				" filename*0*=utf-8'en-US'rebeccapurple;\r\n"
				" filename*1*=%2Dcircle.png;\r\n"
				"\r\n"
				"iVBORw0KGgoAAAANSUhEUgAAABAAAAAQAQMAAAAlPW0iAAAABlBMVEVmM5n///9dvR/iAAAA\r\n"
				"H0lEQVQIHWP4Ic/wgJ3hADNDAyMIYQKIOFABUNkPeQC4LQeH3BOsvgAAAABJRU5ErkJggg==\r\n"
				"\r\n"
				"--==pEp_LoL==--\r\n" // end of multipart/related
				"\r\n"
			"--==pEp_02==--\r\n" // end of multipart/alternative
		"\r\n"
		"--==pEp_01==\r\n" // first "real" attachment, 2nd in bloblist
		"Content-Type: application/octet-stream; name=\"This is a long\r\n"
		" file name so it is split to multiple\r\n"
		" physical lines.bin\"\r\n"
		"Content-Language: en-US\r\n"
		"Content-Transfer-Encoding: base64\r\n"
		"Content-Disposition: attachment;\r\n"
		" filename*0=\"This is a long file name so it is split to\";\r\n"
		" filename*1=\" multiple physical lines.bin\";\r\n"
		"\r\n"
		"w5xiZXJncsO2w59lbsOkbmRlcnVuZyEK\r\n"
		"\r\n"
		"--==pEp_01==\r\n" // another text/plain part, 3rd in bloblist
		"Content-Type: text/plain; charset=\"ISO-8859-15\";\r\n"
		"Content-Transfer-Encoding: quoted-printable\r\n"
		"\r\n"
		"=DCbergr=F6=DFen=E4nderung: 10=A4.\r\n"
		"--==pEp_01==\r\n" // an attached PNG image with bizarre filename as 4th and last element in bloblist
		"Content-Type: image/png; name=\"=?UTF-8?B?8J+SqSDwn5iAIPCf?="
		"  =?UTF-8?B?kqkg8J+YgCDwn5KpIPCfmIAg8J+SqSDwn5iAIPCfkqkg8J+YgCDwn5KpIPCfm?="
		"  =?UTF-8?B?IAg8J+SqSDwn5iAIPCfkqkg8J+YgC5wbmc=?=\"\r\n"
		"Content-Language: en-US\r\n"
		"Content-Transfer-Encoding: base64\r\n"
		"Content-Disposition: attachment;\r\n"
		" filename*0*=utf-8''%F0%9F%92%A9%20%F0%9F%98%80%20%F0%9F%92%A9%20%F0;\r\n"
		" filename*1*=%9F%98%80%20%F0%9F%92%A9%20%F0%9F%98%80%20%F0%9F%92%A9;\r\n"
		" filename*2*=%20%F0%9F%98%80%20%F0%9F%92%A9%20%F0%9F%98%80%20%F0%9F;\r\n"
		" filename*3*=%92%A9%20%F0%9F%98%80%20%F0%9F%92%A9%20%F0%9F%98%80%20;\r\n"
		" filename*4*=%F0%9F%92%A9%20%F0%9F%98%80.png\r\n"
		"\r\n"
		"iVBORw0KGgoAAAANSUhEUgAAABAAAAAQAQMAAAAlPW0iAAAABlBMVEVmM5n///9dvR/iAAAA\r\n"
		"    H0lEQVQIHWP4Ic/wgJ3hADN\r\n"
		"DAyMIYQKIOFABUNkPeQC4LQeH3BOsvgAAAABJRU5ErkJggg==\r\n"
		"--==pEp_01==--\r\n"
		"\r\n";
	
	struct TestEntry
	{
		const char* mail_text;
		const char* mime_type;
		const char* subject;
		const char* text_plain;
		const char* text_html;
		const char* delsp;
		unsigned nr_of_attachments;
	};
	
	std::ostream& operator<<(std::ostream& o, const TestEntry& te)
	{
		return o << "TE{ subject=«" << te.subject << "» } ";
	}
	
	
	const std::string mail_types_common =
		"From: Alice <alice@pep.lol>\r\n"
		"To: Bob <bob@pep.example>\r\n"
		"Date: Tue, 21 May 2019 06:06:06 +1000\r\n"
		"User-Agent: B\r\n"
		"MIME-Version: 1.0\r\n";
	
	// test for all the 16 types of this table:
	// https://dev.pep.foundation/mime-types.png
	const TestEntry mail_types[] =
	{
		{
			"Subject: Test =?UTF-8?Q?=E2=80=9Ctext/plain=E2=80=9D?= Type: 0\r\n"
			"\r\n", // no body at all!
			"text/plain",
			"Test “text/plain” Type: 0",
			nullptr,
			nullptr,
			nullptr, // delsp
			0
		},
		{
			"Subject: Test =?UTF-8?Q?=E2=80=9Ctext/plain=E2=80=9D?= Type: 1\r\n"
			"Content-Type: text/plain; charset=\"ISO-8859-1\"\r\n"
			"Content-Transfer-Encoding: quoted-printable\r\n"
			"\r\n"
			"=DCbergr=F6=DFen=E4nderung.\r\n",
			"text/plain",
			"Test “text/plain” Type: 1",
			"Übergrößenänderung.",
			nullptr,
			nullptr, // delsp
			0
		},
		{
			"Subject: Test =?UTF-8?Q?=E2=80=9Ctext/html=E2=80=9D?= Type: 2\r\n"
			"Content-Type: text/html; charset=\"ISO-8859-1\"\r\n"
			"Content-Transfer-Encoding: quoted-printable\r\n"
			"\r\n"
			"<html><body>=DCbergr=F6=DFen=E4nderung.</body></html>\r\n",
			"text/html",
			"Test “text/html” Type: 2",
			nullptr,
			"<html><body>Übergrößenänderung.</body></html>",
			nullptr, // delsp
			0
		},
		{
			"Subject: Test =?UTF-8?Q?=E2=80=9Cmultipart/alternative=E2=80=9D?= Type: 3\r\n"
			"Content-Type: multipart/alternative; boundary=\"=_X_=\"\r\n"
			"\r\n"
			"--=_X_=\r\n"
			"Content-Type: text/plain; delsp=\"Yes\"; charset=\"ISO-8859-1\"\r\n"
			"Content-Transfer-Encoding: base64\r\n"
			"\r\n"
			"3GJlcmdy9t9lbuRuZGVydW5nLg==\r\n"
			"\r\n"
			"--=_X_=\r\n"
			"Content-Type: text/html charset=\"ISO-8859-1\"\r\n"  // no ; after text/html by intention to test for b0rken MIME headers, too!
			"Content-Transfer-Encoding: base64\r\n"
			"\r\n"
			"PGh0bWw+PGJvZHk+3GJlcmdy9t9lbuRuZGVydW5nLjwvYm9keT48L2h0bWw+\r\n"
			"--=_X_=--\r\n"
			"\r\n",
			"multipart/alternative",
			"Test “multipart/alternative” Type: 3",
			"Übergrößenänderung.",
			"<html><body>Übergrößenänderung.</body></html>",
			"Yes", // delsp
			0
		},
		{
			"Subject: Test \"multipart/mixed\" Type: 4\r\n"
			"Content-Type: multipart/mixed; boundary=\"=_M_=\"\r\n"
			"\r\n"
			"--=_M_=\r\n"
			"Content-Type: image/png;\r\n"
			"Content-Disposition: inline\r\n"
			"Content-Transfer-Encoding: base64\r\n"
			"Content-ID: <079addf6-4566-48e9-a88c-0bca23d527a8@pEp.example>\r\n"
			"\r\n"
			"iVBORw0KGgoAAAANSUhEUgAAABAAAAAQAQMAAAAlPW0iAAAABlBMVEVmM5n///9dvR/iAAAA\r\n"
			"H0lEQVQIHWP4Ic/wgJ3hADNDAyMIYQKIOFABUNkPeQC4LQeH3BOsvgAAAABJRU5ErkJggg==\r\n"
			"--=_M_=--\r\n"
			"\r\n",
			"multipart/mixed",
			"Test \"multipart/mixed\" Type: 4",
			nullptr,
			nullptr,
			nullptr, // delsp
			1
		},
		{
			"Subject: Test \"multipart/mixed\" Type: 5\r\n"
			"Content-Type: multipart/mixed; boundary=\"=_M_=\"\r\n"
			"\r\n"
			"--=_M_=\r\n"
			"Content-Type: image/png;\r\n"
			"Content-Disposition: inline\r\n"
			"Content-Transfer-Encoding: base64\r\n"
			"Content-ID: <1a9d07d9-e799-418f-84c8-5f7c8ae1ba0a@pEp.example>\r\n"
			"\r\n"
			"iVBORw0KGgoAAAANSUhEUgAAABAAAAAQAQMAAAAlPW0iAAAABlBMVEVmM5n///9dvR/iAAAA\r\n"
			"H0lEQVQIHWP4Ic/wgJ3hADNDAyMIYQKIOFABUNkPeQC4LQeH3BOsvgAAAABJRU5ErkJggg==\r\n"
			"--=_M_=\r\n"
			"Content-Type: text/plain; charset=\"UTF-8\"\r\n"
			"\r\n"
			"Kürbis: 4€\r\n"
			"--=_M_=--\r\n"
			"\r\n",
			"multipart/mixed",
			"Test \"multipart/mixed\" Type: 5",
			"Kürbis: 4€",
			nullptr,
			nullptr, // delsp
			1
		},
		{
			"Subject: Test \"multipart/mixed\" Type: 6\r\n"
			"Content-Type: multipart/mixed; boundary=\"=_M_=\"\r\n"
			"\r\n"
			"--=_M_=\r\n"
			"Content-Type: image/png;\r\n"
			"Content-Disposition: inline\r\n"
			"Content-Transfer-Encoding: base64\r\n"
			"Content-ID: <63fdb377-9bc1-4c0a-8252-fe4ed6f91ae9@pEp.example>\r\n"
			"\r\n"
			"iVBORw0KGgoAAAANSUhEUgAAABAAAAAQAQMAAAAlPW0iAAAABlBMVEVmM5n///9dvR/iAAAA\r\n"
			"H0lEQVQIHWP4Ic/wgJ3hADNDAyMIYQKIOFABUNkPeQC4LQeH3BOsvgAAAABJRU5ErkJggg==\r\n"
			"--=_M_=\r\n"
			"Content-Type: text/html; charset=\"UTF-8\"\r\n"
			"\r\n"
			"<html><body>Kürbis: 4€</body></html>\r\n"
			"--=_M_=--\r\n"
			"\r\n",
			"multipart/mixed",
			"Test \"multipart/mixed\" Type: 6",
			nullptr,
			"<html><body>Kürbis: 4€</body></html>",
			nullptr, // delsp
			1
		},
		{
			"Subject: Test \"multipart/mixed\" Type: 7\r\n"
			"Content-Type: multipart/mixed; boundary=\"=_MM_=\"\r\n"
			"\r\n"
			"--=_MM_=\r\n"
			"Content-Type: image/png;\r\n"
			"Content-Disposition: inline\r\n"
			"Content-Transfer-Encoding: base64\r\n"
			"Content-ID: <e134a9aa-02ab-45ab-b1d0-0be23a9a0d44@pEp.example>\r\n"
			"\r\n"
			"iVBORw0KGgoAAAANSUhEUgAAABAAAAAQAQMAAAAlPW0iAAAABlBMVEVmM5n///9dvR/iAAAA\r\n"
			"H0lEQVQIHWP4Ic/wgJ3hADNDAyMIYQKIOFABUNkPeQC4LQeH3BOsvgAAAABJRU5ErkJggg==\r\n"
			"--=_MM_=\r\n"
			"Content-Type: text/html; charset=\"UTF-8\"\r\n"
			"\r\n"
			"<html><body>Kürbis: 4€</body></html>\r\n"
			"--=_MM_=\r\n"
			"Content-Type: text/plain; charset=\"UTF-8\"\r\n"
			"\r\n"
			"Kürbis: 4€\r\n"
			"--=_MM_=--\r\n"
			"\r\n",
			"multipart/mixed",
			"Test \"multipart/mixed\" Type: 7",
			"Kürbis: 4€",
			"<html><body>Kürbis: 4€</body></html>",
			nullptr, // delsp
			1 // HTML and PNG as attachment, because it is _not_ multipart/alternative!
		},
	};

	// to test the MIME parser whether it handles non-standard line endings
	struct TestEntryLineEnding
	{
		const char* const name;
		std::string (*converter)(const char* mime_text);
	};
	
	const TestEntryLineEnding lineendings[] =
	{
		{ "CRLF", [](const char* mime_text){ return std::string(mime_text); } },
		{ "CR"  , [](const char* mime_text){ return boost::algorithm::replace_all_copy(std::string(mime_text), "\r\n", "\r"); } },
		{ "LF"  , [](const char* mime_text){ return boost::algorithm::replace_all_copy(std::string(mime_text), "\r\n", "\n"); } },
	};

} // end of anonymous namespace


class MimeTestP : public ::testing::TestWithParam<TestEntry>
{
    // intentionally left blank for now.
};

INSTANTIATE_TEST_CASE_P(MimeTestPInstance, MimeTestP, testing::ValuesIn(mail_types) );

TEST_P( MimeTestP, MimeTypes )
{
    const auto& p = GetParam();
    const std::string f = mail_types_common + p.mail_text;
    
    message* m = pEpMIME::parse_message(f.data(), f.size());
    ASSERT_NE( m, nullptr );
    
    EXPECT_STREQ(m->shortmsg, p.subject);
    EXPECT_STREQ(m->longmsg, p.text_plain);
    EXPECT_STREQ(m->longmsg_formatted, p.text_html);
    
    const stringpair_list_t* const delsp = stringpair_list_find(m->opt_fields, pEpMIME::Pseudo_Header_Delsp.data());
    if(p.delsp)
    {
        ASSERT_NE(delsp, nullptr);
        EXPECT_STREQ(delsp->value->value, p.delsp);
    }else{
        EXPECT_EQ(delsp, nullptr);
    }
    
    EXPECT_EQ( bloblist_length(m->attachments), p.nr_of_attachments);
    
    std::cerr << "Opt-Fields: " << pEpMIME::out(m->opt_fields) << "\n";
    const stringpair_list_t* t = stringpair_list_find( m->opt_fields, "Content-Type");
    if(t)
    {
        sv ct_line{t->value->value};
        const pEpMIME::ContentType ct{ct_line};
        EXPECT_EQ( ct.mime_type(), p.mime_type );
    }
    
    if(delsp)
    {
        char* c = pEpMIME::generate_message(m, false, true);
        ASSERT_NE( c, nullptr );
        std::cout << "§§§§§§ GENERATED DELSP MESSAGE: §§§§§§" << std::endl;
        std::cout << c << std::endl;
        std::cout << "§§§§§§§§§§§§§§§§§§" << std::endl;
        free(c);
    }
    
    free_message(m);
}


class MimeTestLineEndingP : public ::testing::TestWithParam<TestEntryLineEnding>
{
    // intentionally left blank for now.
};

INSTANTIATE_TEST_CASE_P(MimeTestLineEndingPInstance, MimeTestLineEndingP, testing::ValuesIn(lineendings) );


TEST_P(MimeTestLineEndingP, Nested)
{   
    const auto& p = GetParam();
    const std::string f = p.converter(mail1_eml);
    
    message* m = pEpMIME::parse_message(f.data(), f.size());
    ASSERT_NE( m, nullptr );
    
    std::cerr << "\n§§§§§§§§§§§<BEGIN: " << p.name << ">§§§§§§§§§\n";
    pEpMIME::print_message(m);
    std::cerr << "§§§§§§§§§§§<END: " << p.name << ">§§§§§§§§§\n\n";
    EXPECT_STREQ( m->from->username, "Alice");
    EXPECT_STREQ( m->shortmsg, "Rødgrød med fløde" );
    EXPECT_EQ( std::string(m->longmsg) , p.converter("Rødgrød med fløde?\r\n") );
    EXPECT_EQ( identity_list_length(m->to), 1 );
    EXPECT_EQ( identity_list_length(m->cc), 4 );
    EXPECT_EQ( identity_list_length(m->bcc), 0 );
    EXPECT_EQ( bloblist_length(m->attachments), 4 );
    
    auto a = m->attachments;
    while(a)
    {
        std::cerr << "§§ mime_type=" << a->mime_type << ".\n";
        a = a->next;
    }
    
    const bloblist_t* att1 = m->attachments;
    ASSERT_NE( att1, nullptr );
    EXPECT_STREQ( att1->mime_type, "image/png" );
    EXPECT_STREQ( att1->filename, "rebeccapurple-circle.png" );
    
    const bloblist_t* att2 = att1->next;
    ASSERT_NE( att2, nullptr );
    
    EXPECT_STREQ( att2->mime_type, "application/octet-stream" );
    EXPECT_STREQ( att2->filename, "This is a long file name so it is split to multiple physical lines.bin" );
    EXPECT_STREQ( att2->value, "Übergrößenänderung!\n" );

    const bloblist_t* att3 = att2->next;
    ASSERT_NE( att3, nullptr );

    EXPECT_STREQ( att3->mime_type, "text/plain" );
    EXPECT_STREQ( att3->value, "\xDC" "bergr\xF6\xDF" "en\xE4" "nderung: 10\xA4." );  // no convertion to UTF-8 in attachments!
    
    const bloblist_t* att4 = att3->next;
    ASSERT_NE( att4, nullptr );
    
    EXPECT_STREQ( att4->filename, u8"\U0001f4a9 \U0001f600 \U0001f4a9 \U0001f600 \U0001f4a9 \U0001f600 \U0001f4a9 \U0001f600 \U0001f4a9 \U0001f600 \U0001f4a9 \U0001f600 \U0001f4a9 \U0001f600 \U0001f4a9 \U0001f600.png" );
    EXPECT_EQ( att4->size, 106 );
    
    const std::string data = std::string(att4->value, att4->value + att4->size);
    EXPECT_EQ( data, std::string(
        "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A\x00\x00\x00\x0D\x49\x48\x44\x52"
        "\x00\x00\x00\x10\x00\x00\x00\x10\x01\x03\x00\x00\x00\x25\x3D\x6D"
        "\x22\x00\x00\x00\x06\x50\x4C\x54\x45\x66\x33\x99\xFF\xFF\xFF\x5D"
        "\xBD\x1F\xE2\x00\x00\x00\x1F\x49\x44\x41\x54\x08\x1D\x63\xF8\x21"
        "\xCF\xF0\x80\x9D\xE1\x00\x33\x43\x03\x23\x08\x61\x02\x88\x38\x50"
        "\x01\x50\xD9\x0F\x79\x00\xB8\x2D\x07\x87\xDC\x13\xAC\xBE\x00\x00"
        "\x00\x00\x49\x45\x4E\x44\xAE\x42\x60\x82", 106 )
        );
    
    char* c = pEpMIME::generate_message(m, false, true);
    ASSERT_NE( c, nullptr );
    std::cout << "###### GENERATED MESSAGE: ######" << std::endl;
    std::cout << c << std::endl;
    std::cout << "##################" << std::endl;
    
    pEp_free(c);
    free_message(m);
}
