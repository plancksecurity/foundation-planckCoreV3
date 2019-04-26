p≡p Sync protocol
=================

1. Protocol Stack
-----------------

Key Sync | Trust Sync | Contact Sync | Task Sync
Sync
Baseprotocol
Transport

1. Group View
--------------

1.1 Sender

A Sender is the Person sending a message. In case of M2M it is the Operating
Entity of the Device sending.

1.1 Device

A Device is an entitiy, which is sending representative of a Sender.

1.1 State Sole

A Device is in state Sole when it is not member of a Device group and when it
is not part of a Negotiation.

1.1 State Grouped

A Device is in state Grouped when it is member of a Device group and when it is
not part of a Negotiation.

1. Transaction View for Negotiation
-----------------------------------

1.1 TID

A TID (transaction ID) is a UUID version 4 variant 1.

1.1 Challenge

The Challenge is identified by a TID. The Challenge is being set by each Beacon
and must be repeated in a corresponding HandshakeRequest.

1.1 Negotiation

A Negotiation is a transaction identified by a TID.

1. Roles and Keys
-----------------

1.1 Sender signing

The key with which the Sender of the message is signing. In case of trusted
messages this is signalled within the encrypted message. This is signalled by
by opt_field pEp-sender-sign, which is not reflected to the outer message.

Transports can opt to use HMAC or OMAC instead of digital signatures.

1.1 Transport signing

Keys with which others and not the Sender are signing a message.

1.1 Sender Group key

A Sender Group Key is a Sender's signing key, which is used to update the
Device Group information. If it is reset the Device Groups breaks.

