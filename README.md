<!-- Copyright 2015-2017, pEp foundation, Switzerland
This file is part of the pEp Engine
This file may be used under the terms of the Creative Commons Attribution-ShareAlike 3.0 Unported (CC BY-SA 3.0) License
See CC_BY-SA.txt -->

# What is the p≡p Engine?
The p≡p Engine is a Free Software library encapsulating implementations of:

- Key Management

  Key Management in the p≡p Engine is based on GnuPG key chains (NetPGP on iOS).
  Keys are stored in an OpenPGP-compatible format, and can be used for different crypto implementations.

- Trust Rating

  The p≡p Engine sports a two phase trust rating system for messages:
  In phase one a rating is derived based on channel, crypto and key security.
  This is named "comm\_types".
  In phase two these ratings are mapped to user-representable values mimicking the semantics of a traffic light.

- Abstract Crypto API

  The Abstract Crypto API provides functions to encrypt and decrypt data or full messages, without requiring an application programmer to understand the different applied formats and standards.

- Message Transports

  The p≡p Engine will sport a growing list of message transports, to support any widespread text-based messaging system such as E-Mail, SMS, XMPP and many more.

The p≡p Engine is written in C99 and is expected to run on any platform that conforms to the SUS/POSIX specification.
Selected non-SUS platforms are supported as well (such as Microsoft Windows).

# How can I use the p≡p Engine?
Build instructions can be found in the "doc/" subfolder in this repository.
The p≡p Engine is not meant to be used in application code directly.
Instead, the p≡p Engine is meant to be used in conjunction with a so-called "adapter".
An adapter provides an API in a programming language that best accomodates developers in their respective software development ecosystem.
So, for example, a Java Native Interface adapter exists for development of apps for the Android mobile operating system, or a .NET adapter exists for development of applications on Microsoft Windows.
Various adapters are also available at the link provided for the p≡p Engine's code above.

# What is the current state of the project?
The p≡p Engine is production-ready.
It is under active development by several full-time employees of the p≡p foundation and its partner organizations.
The most recent version of the source code can be obtained here: <https://pep.foundation/dev/repos>.
This is the only offical way to obtain a copy of the source code.

# I would like to contribute to the p≡p Engine or a related project, where do I start?
First of all, excellent! You can find further information here: <https://contribution.pep.foundation/>

# Legal notes
The p≡p Engine is Copyright 2015-2020 by p≡p foundation, Switzerland.
The source code of the p≡p Engine is licensed under the terms of the GNU General Public License version 3.
Accompanying documentation is licensed under the terms of the Creative Commons Attribution-ShareAlike 3.0 Unported (CC BY-SA 3.0) License.
Each file includes a notice near its beginning, that indicates the applicable license.
If you wish to license the p≡p Engine under different terms, please contact <mailto:council@pep.foundation>.

_pEp_reallocarray in pgp_sequoia.c is reallocarray from the OpenBSD source. It is 
copyright (c) 2008 Otto Moerbeek <otto@drijf.net> with the following permissions: 
Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

# Contact
The p≡p foundation and the developers of the p≡p Engine can be reached as detailed here: <https://pep.foundation/contact-us/index.html>.
