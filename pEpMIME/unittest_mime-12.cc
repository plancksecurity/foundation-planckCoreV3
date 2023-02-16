// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "pEpMIME.hh"
#include "pEpMIME_internal.hh" // for Pseudo_Header_Forwarded
#include "headerparser.hh"
#include "mime_headers.hh"
#include "print_message.hh"
#include "base64.hh"
#include "../src/mime.h"
#include <iostream>
#include <gtest/gtest.h>

using namespace std::string_literals;

namespace
{
    static const sv mail1 =
        "X-Mozilla-Status: 0001\r\n"
        "X-Mozilla-Status2: 00000000\r\n"
        "X-Mozilla-Keys: \r\n"
        "X-Envelope-From: <alice@pep.lol>\r\n"
        "X-Envelope-To: <janet@pop.lol>\r\n"
        "X-Delivery-Time: 1580000000\r\n"
        "X-Uid: 100\r\n"
        "Return-Path: <alice@pep.lol>\r\n"
        "Authentication-Results: lol.com; dmarc=none header.from=pep.lol.com;\r\n"
        " arc=nonepep-com.aq; dkim=nonepep-com.aq; dkim-adsp=none\r\n"
        " header.from=\"alice@pep.lol\"pep-com.aq; spf=none\r\n"
        " smtp.mailfrom=\"alice@pep.lol\"\r\n"
        "X-Rzg-Expurgate: clean/normal\r\n"
        "X-Rzg-Expurgate-Id: 111:1111111-11111-11111/0/0\r\n"
        "X-Rzg-Class-Id: xxx\r\n"
        "Received-Spf: none\tclient-ip=10.10.10.10;\thelo=\"dragonlord.pep.lol\";\tenvelope-from=\"alice@pep.lol\";\treceiver=smtpin.rzone.de;\tidentity=mailfrom;\r\n"
        "Received: from dragonlord.pep.lol ([10.10.10.10])\tby smtpin.rzone.de (RZmta 46.4.1\r\n"
        " OK)\twith ESMTPS id sssssssssssssss\t(using TLSv1.3 with cipher\r\n"
        " TLS_AES_256_GCM_SHA384 (256 bits))\t(Client did not present a\r\n"
        " certificate)\tfor <janet@pop.lol>;\tThu, 16 Apr 2020 22:22:22\r\n"
        " +0200 (CEST)from localhost (localhost [127.0.0.1])\tby dragonlord.pep.lol\r\n"
        " (Postfix) with ESMTP id aaaaaaaaaaaa\tfor <janet@pop.lol>; Thu,\r\n"
        " 16 Apr 2020 22:22:22 +0200 (CEST)from dragonlord.pep.lol ([127.0.0.1])\tby\r\n"
        " localhost (dragonlord.pep.lol [127.0.0.1]) (amavisd-new, port 11111)\twith\r\n"
        " ESMTP id zzzzzzzzzzzz for <janet@pop.lol>;\tThu, 16 Apr 2020\r\n"
        " 22:22:22 +0200 (CEST)from pEplol.home\r\n"
        " (xx  [10.1.111.111])\tby\r\n"
        " dragonlord.pep.lol (Postfix) with ESMTPSA id 777777777777\tfor\r\n"
        " <janet@pop.lol>; Thu, 16 Apr 2020 22:22:22 +0200 (CEST)\r\n"
        "Date: Thu, 16 Apr 2020 22:22:22 +0200\r\n"
        "From: Alice Keylesst <alice@pep.lol>\r\n"
        "To: \"janet@pop.lol\" <janet@pop.lol>\r\n"
        "Subject: =?UTF-8?B?cOKJoXA=?=\r\n"
        "Message-Id: pEp.example.xxx@pep.foundation\r\n"
        "In-Reply-To: \r\n"
        "References: \r\n"
        "X-Pep-Version: 2.1\r\n"
        "Mime-Version: 1.0\r\n"
        "Content-Type: multipart/mixed; boundary=\"=pEp-MIME-12-O=\"\r\n"
        "Content-Transfer-Encoding: 7bit\r\n"
        "\r\n"
        "--=pEp-MIME-12-O=\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/mixed; boundary=\"=pEp-MIME-12-M=\"\r\n"
        "\r\n"
        "--=pEp-MIME-12-M=\r\n"
        "Content-Type: text/plain; charset=\"utf-8\"\r\n"
        "\r\n"
        "This message was encrypted with p≡p (https://pep.software). If you are seeing this message,\r\n"
        "your client does not support raising message attachments. Please click on the message attachment to\r\n"
        "to view it, or better yet, consider using p≡p!\r\n"
        "\r\n"
        "--=pEp-MIME-12-M=\r\n"
        "Content-Type: message/rfc822; forwarded=\"no\"\r\n"
        "\r\n"
        "Message-ID: <<xxxx5zthgbewrte@pretty.Easy.privacy>>\r\n"
        "Date: Thu, 16 Apr 2020 11:11:11 +0000\r\n"
        "From: Alice Keylesst <alice@pep.lol>\r\n"
        "To: \"janet@pop.lol\" <janet@pop.lol>\r\n"
        "Subject: Test message\r\n"
        "X-pEp-Version: 2.1\r\n"
        "X-pEp-Wrapped-Message-Info: INNER\r\n"
        "X-pEp-Sender-FPR: xxxxxxxxxxxxxxxxxx\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/alternative; boundary=\"=pEp-MIME-12-A=\"\r\n"
        "\r\n"
        "--=pEp-MIME-12-A=\r\n"
        "Content-Type: text/plain; charset=\"utf-8\"\r\n"
        "Content-Transfer-Encoding: quoted-printable\r\n"
        "\r\n"
        "Yay=21 A message=21 =20\r\n"
        "--  Sent from my p=E2=89=A1p for Android.\r\n"
        "--=pEp-MIME-12-A=\r\n"
        "Content-Type: text/html; charset=\"utf-8\"\r\n"
        "Content-Transfer-Encoding: quoted-printable\r\n"
        "\r\n"
        "Yay=21 A message=21 <br>\r\n"
        "--  Sent from my p=E2=89=A1p for Android.\r\n"
        "--=pEp-MIME-12-A=--\r\n"
        "\r\n"
        "--=pEp-MIME-12-M=\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Disposition: attachment; filename=\"lolcat.bin\"\r\n"
        "\r\n"
        "3mpygMDV7qzDDz6RRy1bz+HrwUGuNlyCqbsHEjgOE1EiyhblocGFI8ykYG+vzSdW\r\n"
        "F48Emz15CBVKRTfnkN/QWsxEJZAhTHvHPb8McDpQ0C94cNuRGL1P6+gVaRDHq4fW\r\n"
        "\r\n"
        "--=pEp-MIME-12-M=--\r\n"
        "--=pEp-MIME-12-O=--\r\n"
        "\r\n";
}

std::ostream& operator<<(std::ostream& o, const stringpair_list_t* spl)
{
    if(spl==nullptr)
    {
        return o << "SPL(NULL)";
    }
    
    o << "SPL:\n";
    while(spl)
    {
        o << "\t key=\"" << spl->value->key << "\", value=\"" << spl->value->value << "\"\n";
        spl = spl->next;
    }
    
    return o;
}


TEST( MimeTest12, Good )
{
    bool raise = false;
    message* m = pEpMIME::parse_message(mail1.data(), mail1.size(), &raise);
    ASSERT_NE( m, nullptr );
    
    EXPECT_TRUE(raise);
    
    std::cout << "°°°°°°°°°°°°°°°°\n" << m->opt_fields << "\n++++++++++++++\n";
    
    free_message(m);
}
