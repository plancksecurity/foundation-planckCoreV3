pEp Engine
==========

0. What is it
1. How to use it
2. Who is providing this, and how is it provided

0. What is it
-------------

pEp Engine is an implementation of the p≡p standard as a portable C library.
pEp Engine is written for being used on Windows, MacOS X, iOS, Android and
GNU/Linux. It is meant to be used on other POSIX compliant systems as well.

The p≡p standard defines how to use encryption and key management for message
based communication between persons. It specifies a metric for encryption
channels like OpenPGP or CMS, which then are applied on message transports like
Internet Mail, SMS or WhatsApp. Additionally, the p≡p standard defines how to
use GNUNet for implementing messaging where meta data can be hidden from
eavesdroppers.

1. How to use it
----------------

pEp Engine never should be used by an application programmer directly. It is
meant to be used by an adapting implementation which removes most of the attack
vectors usually offered by C code and common application programming mistakes.
Such an adapter must not be written in C. If possible, it must be written in a
safe language without the problems pointers bring in. If this is not possible,
the adapter must be written in an unsafe language like C++, but the interface
to the application programmer has to implement safety against such application
programmer mistakes.

pEp Engine is offering keymanagement.h. This should be the only interface which
is being used by an adapter. The documentation is in this header file. If this
cannot be done, because an adapter needs more internal access to pEp Engine,
there is the additional interface in pEpEngine.h. This may be used while it is
recommended not to use it. Only if there is no other way for the programmer of
the adapter pEpEngine.h should be used. This is true for opening and closing a
session to pEp Engine.

