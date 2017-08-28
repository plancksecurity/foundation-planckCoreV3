<!-- Copyright 2015-2017, pEp foundation, Switzerland
This file is part of the pEp Engine
This file may be used under the terms of the Creative Commons Attribution-ShareAlike 3.0 Unported (CC BY-SA 3.0) License
See CC_BY-SA.txt -->

# Information about the pEp Engine

# Dependencies
The p≡p Engine depends on the following projects:

- run-time dependencies
  - One of the following OpenPGP implementations:
    - GnuPG (version 2.0.30 or 2.1.16 or newer) by way of GPGME (version 1.6.0 or newer) [https://gnupg.org/](https://gnupg.org/)
    - a fork of NetPGP, [https://cacert.pep.foundation/dev/repos/netpgp-et/](https://cacert.pep.foundation/dev/repos/netpgp-et/)
  - a fork of libetpan, [https://github.com/fdik/libetpan](https://github.com/fdik/libetpan)
  - zlib (Oh yeah, where?), [http://zlib.net/](http://zlib.net/)
  - OpenSSL (Oh yeah, where?), [https://www.openssl.org](https://www.openssl.org)
  - Cyrus SASL (Oh yeah, where?), [https://www.cyrusimap.org](https://www.cyrusimap.org)
  - libcurl (Oh yeah, where?), [https://curl.haxx.se/libcurl/](https://curl.haxx.se/libcurl/)
  - libuuid, [https://www.kernel.org/pub/linux/utils/util-linux/](https://www.kernel.org/pub/linux/utils/util-linux/)
  - SQLite, [https://sqlite.org](https://sqlite.org)
- compile-time dependencies
  - asn1c (version v0.9.28), [http://lionet.info/asn1c/blog/](http://lionet.info/asn1c/blog/)
  - yml2, [https://fdik.org/yml//toolchain](https://fdik.org/yml//toolchain)
  - One of the following build systems:
    - GNU make (on Linux and macOS)
    - MSBuild distributed with Microsoft Visual Studio 2015 (on Windows)
  - One of the following compilers for C and C++:
    - GNU GCC (on Linux)
    - Apple "clang" LLVM (on MacOS)
    - Microsoft MSVC/MSVC++ distributed with Microsoft Visual Studio 2015 (on Windows)

# The pEp Engine's databases
The p≡p Engine uses two databases:
`~/.pEp_management` (on *NIX) or `%LOCALAPPDATA%\pEp\management.db` on Windows, and `/usr/local/share/system.db` (on *NIX) or `%ALLUSERSPROFILE%\pEp\system.db`.
The latter contains the Trustwords databases.

The management db is created by the first call of init() of p≡p Engine.
It does not need to be created manually.
`system.db` is created by using the DDL in `db/create_system_db.sql`; the database content is created by `db/dic2csv.py` out of hunspell's dictionary packages (or something similar) and then imported using `sqlite3`'s `.import` command.
Dictionary files for different languages are part of the p≡p Engine source distribution.

You can test the Trustwords in `system.db` using `db/trustwords.py`.
Both Python tools have a `--help` switch.