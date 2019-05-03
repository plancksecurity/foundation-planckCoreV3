# p≡p Sync protocol

## Protocol Stack

Key Sync | Trust Sync | Contact Sync | Task Sync
- | - | - | -
Sync
Baseprotocol
Transport

## Forming a Device Group with Key Sync

### Sender

A Sender is the Person sending a message. In case of M2M it is the Operating
Entity of the Device sending.

### Device

A Device is an entitiy, which is sending representative of a Sender.

### State Sole

A Device is in state Sole when it is not member of a Device group and when it
is not part of a Negotiation.

### State Grouped

A Device is in state Grouped when it is member of a Device group and when it is
not part of a Negotiation.

## Negotiation as a Transaction

### TID

A TID (transaction ID) is a UUID version 4 variant 1.

### Challenge

The Challenge is identified by a TID. The Challenge is being set by each Beacon
and must be repeated in a corresponding Negotiation Request. The Challenge has
two functions:

1. The Challenge makes it possible to filter out own Beacons
1. The Challenge makes it necessary to be able to read the communication
   channel (usually an Inbox), otherwise Beacons cannot be answered

### Negotiation

A Negotiation is a Transaction identified by a TID. The Negotiation's TID is
the XOR of the two Challenge TIDs of the two devices, respectively.

## Roles and Keys

### Sender signing

The key with which the Sender of the message is signing. In case of trusted
messages this is signalled within the encrypted message. This is signalled by
by opt_field pEp-sender-sign, which is not reflected to the outer message.

Transports can opt to use HMAC or OMAC instead of digital signatures.

### Transport signing

Keys with which others and not the Sender are signing a message.

### Sender Group key

A Sender Group Key is a Sender's signing key, which is used to update the
Device Group information. If it is reset the Device Groups breaks.

