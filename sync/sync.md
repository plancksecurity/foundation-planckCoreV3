# p≡p KeySync

KeySync is a protocol of the p≡p Sync family. It is defined in
`pEpEngine/sync/sync.fsm`.

The Use Cases of KeySync are:

- to discover other Devices of the same User, which are using the same Accounts
- to form a Device Group with these Devices
- to join an already existing Device Group in case of a new Device
- to share all Own Identities and all Own Keys within the Device Group

## Sync Communication Channels

p≡p Sync is designed for Communication Channels with the following properties:

- Broadcast: any Message sent will reach all Devices
- Read Protected: while it is not a problem if arbitrary senders can send
  Messages to the Communication Channel, it must be impossible for
  unauthenticated Devices to read from the Channel.
- Offline Channel: there can be no way of deciding, which Devices are on the
  channel and if they're reading or not.

Examples for Sync Communication Channels are an Inbox of an Account or an MQ
Topic.

p≡p Sync is requiring at least one common Communication Channel between all
Devices in a Device Group.

## Graphical representation of the KeySync Finite State Machine

![Finite State Machine for KeySync](/keysync.svg)

## State Machine Model

The p≡p Sync protocols are implemented using a State Machine each. The State
Machine Model for p≡p Sync is defined in `pEpEngine/sync/sync.fsm`. This file
is written using the [YML2 tool chain](https://fdik.org/yml). The syntax of the
Model is defined by [declaring functions](https://fdik.org/yml/features#decl)
in `pEpEngine/sync/fsm.yml2`.

##### Syntax

    decl protocol @name (id, threshold=10);

##### Definition

    protocol Sync 1

Defines the Sync Protocol Family with ID 1.

### State Machine

KeySync is defined as Finite State Machine.

##### Syntax

    decl fsm @name (id, threshold=10);

##### Definition

    fsm KeySync 1, threshold=300

Defines the State Machine for the KeySync Protocol with ID 1 and a Threshold of
300 seconds until a the timeout Event occurs.

### States

A State Machine is always in one State.

##### Syntax

    decl state @name (timeout=on);

#### InitState

    state InitState

When a State Machine is initialized, it is in InitState.
    
#### Stable States

The State Machine of KeySync has two Stable States, which are not timing out:

##### Sole

    state Sole timeout=off

KeySync is in this State while the Device is not yet member of a Device Group.

##### Grouped

    state Grouped timeout=off

KeySync is in this State while the Device is member of a Device Group.

#### Transitional States

All other states are Transitional States. Those are documented in the [Use
Cases chapter](#use-cases).

### Events

While being in a State it can happen that an Event occurs. In this case the
corresponding Event Handler will be executed.

##### Syntax

    decl event @name, on is event;

#### Init Event

When the State Machine transitions to a State the Init event is happening to
this State. If an Init Event Handler is present for this State this Event
Handler is called. The Event Handler may contain [Conditions](#conditions),
[Actions](#actions), sending of [Messages](#messages) and
[Transitions](#transitions). All States can have a handler for an Init event,
including the `InitState`.

##### Sample

    state InitState { on Init { if deviceGrouped { send SynchronizeGroupKeys;
    go Grouped; } go Sole; } }

#### Message Event

If a Sync Message arrives through the Network then the Event with the name of
the Message is occuring.

##### Sample

In this example an Event Handler is defined, which is executed when a Beacon
Message arrives:

    on Beacon { do openNegotiation; do tellWeAreGrouped; do useOwnResponse;
    send NegotiationRequestGrouped; do useOwnChallenge; }

#### Signaled Events

Events, which don't share their name with a Message, are being signaled from
engine code.

##### Sample

The KeyGen Event has no corresponding Message. Therefore, it is not occuring
when a Sync Message arrives but when it is signaled from code:

    on KeyGen { do prepareOwnKeys; send GroupKeysUpdate; }

The signalling can be done by calling `signal_Sync_event()`:

    // call this if you need to signal an external event // caveat: the
    ownership of own_identities goes to the callee

    PEP_STATUS signal_Sync_event( PEP_SESSION session, Sync_PR fsm, int event,
    identity_list *own_identities);

##### Sample

In this example the KeyGen event is signaled to KeySync when a new Own Key is
generated:

    signal_Sync_event(session, Sync_PR_keysync, KeyGen, NULL);

#### External Event IDs

If Events are part of an API then their IDs must be well defined. Therefore, it
is possible to define such IDs in the State Machine.

##### Syntax

    decl external @name (id);

##### Sample

    external Accept 129;

### Transitions

To switch to another State it is possible to write a Transition into an Event
Handler.

##### Syntax

    decl transition @target, go is transition;

##### Sample

In this example there are two Transitions, one to State Grouped and one to
State Sole:

    on Init { if deviceGrouped { send SynchronizeGroupKeys; go Grouped; } go
    Sole; }

### Messages

KeySync is a Network Protocol, which is implemented using Sync Messages. The
Sync Messages for KeySync are defined at the end of the Finite State Machine in
`pEpEngine/sync/sync.fsm`.

The wire format of Sync Messages is defined in
[ASN.1](https://en.wikipedia.org/wiki/Abstract_Syntax_Notation_One), see
`pEpEngine/asn.1/keysync.asn1`, using
[PER](https://en.wikipedia.org/wiki/Abstract_Syntax_Notation_One#Packed_Encoding_Rules).

Sync Messages are transported as Attachments to p≡p Messages. Hence they're
transported by the same Transports, which are transporting p≡p Messages. Some
Sync Messages must be sent in copy on all Transports. Others are transported on
the Active Transport only. The Active Transport is the Transport, on which the
last Sync Message was received.

Each Sync Message has a name and an ID. There is different types of Messages:

- `type=broadcast` for Messages, which are meant to be copied on all Transports
- `type=anycast` for Messages, which are meant to be sent on the Active
  Transport only

Each Sync Message has a Security Context. The available Security Contexts are:

- `security=unencrypted`: send and receive as unencrypted but signed Sync
  Message
- `security=untrusted`: only accept when encrypted and signed
- `security=trusted` (default): only accept when coming over a Trusted Channel
  and when originating from the Device Group
- `security=attach_own_keys_for_new_member`: like `security=trusted` but attach
  all Own Keys for a new Member of the Device Group
- `security=attach_own_keys_for_group`: like `security=trusted` but atttach all
  Own Keys for other Device Group Members.

A Sync Message can have a Rate Limit `ratelimit=<numeric>`. That means it is
only possible to send out one message each `<numeric>` seconds. A Rate Limit of
0 means no Rate Limit checking.

##### Syntax

    decl message @name (id, type=anycast, security=trusted, ratelimit=0);

##### Sample

    message Beacon 2, type=broadcast, ratelimit=10, security=unencrypted {
    field TID challenge; auto Version version; }

#### Fields

A Sync Message can have Fields. There is two types of fields: automatically
calculated fields, defined with the `auto` keyword, and fields, which are
copied in and out from the I/O buffer, marked with the `fields` keyword.

The wire format of the fields is depending on their type. The types are defined
in `pEpEngine/asn.1/pEp.asn1`. Additionally, the two basic types `bool` (ASN.1:
BOOLEAN) and `int` (ASN.1: INTEGER) are supported.

##### Syntax

    decl field @type @name; decl auto < field >;

##### Sample for an `auto` field:

    auto Version version;

This field will be filled with the p≡p Sync Protocol version. The `Version`
type is the only automatically calculated type yet.

##### Sample for an field coming from I/O buffer

    field TID challenge;

#### I/O Buffer

There is an I/O Buffer for all Fields, which are occuring in Messages. All
Messages share this I/O buffer. Fields with the same name share one space in
the I/O Buffer. Hence, the I/O Buffer is built as superset of all Fields'
buffers.

#### Sending

Sending is being done by:

1. Calculating all `auto` Fields and copying the result into the I/O Buffer
1. Loading all Fields of the Message from I/O Buffer
1. Creating a Sync Message
1. Creating a transporting p≡p Message by attaching the Sync Message using Base
Protocol
1. Calling `messageToSend()` with this p≡p Message

##### Syntax

    decl send @name;

##### Sample

    send SynchronizeGroupKeys;

#### Receiving

When a Message is being received the field values are being copied into the I/O
Buffer and the corresponding [Event](#events) is being signaled.

### Conditions

Conditions are implemented in `pEpEngine/sync/cond_act_sync.yml2` with the
keyword `condition`. All implemented Conditions can be used in any Sync
Protocol. A [dangling else](https://en.wikipedia.org/wiki/Dangling_else) and
[nesting](https://en.wikipedia.org/wiki/Nesting_(computing)) of Conditions are
supported. Hence, Conditions can contain all elements, which can be contained
by Event Handlers, too. All Conditions can either be true or false on success,
or they fail and are bringing the State Machine into an error state, and the
State Machine will be initialized.

##### Syntax

    decl condition @name, if is condition; decl else;

##### Sample

Checking the Condition `sameResponse` and executing Actions and Transitions
depending on its result:

    if sameResponse { // the first one is from us, we're leading this do
    resetOwnGroupedKeys; go Grouped; } else { // the first one is not from us
    go Grouped; }

The implemented Conditions are:

#### condition deviceGrouped

True if the Device is already member of a Device Group. This is determined by
checking if there are Group Keys already.

#### condition fromGroupMember

For double checking. True is the incoming Sync Message is coming from a Device
Group member.

#### condition keyElectionWon

True if our Own Keys are going to be used as Group Keys. False if the Own Keys
of the partner will be the Group Keys. Calculated by comparing if the FPR of
the Sender Key of the partner is greater than our Default Key for the Account,
which is being used as Active Transport.

#### condition sameChallenge

True if the Challenge of the incoming Sync Message is identical to the
Challenge of the Device. In this case this was a Sync Message sent by the
Device itself.

#### condition sameNegotiation

True if the Negotiation of the incoming Sync Message is identical to the
Negotiation the Device is in. In this case the incoming Sync Message is part of
the same Negotiation.

#### condition sameNegotiationAndPartner

True if the Negotiation of the incoming Sync Message is identical to the
Negotiation the Device is in and the partner did not change. In this case the
incoming Sync Message is part of the same Negotiation coming from the expected
Device.

#### condition sameResponse

True if the Response of the incoming Sync Message is identical to the Response
of the Device. In this case the Response was correctly echoed.

#### condition weAreOfferer

True if the Challenge of the incoming Sync Message is greater than the
Challenge of the Device. Otherwise we're Requester.

### Actions

Actions are implemented in `pEpEngine/sync/cond_act_sync.yml2` with the keyword
`action`. All implemented Actions can be used in any Sync Protocol. Actions are
unconditionally executing the code of their implementation. All Actions may
fail. In this case they're bringing the State Machine into an error state, and
the State Machine will be initialized.

##### Syntax

    decl action @name, do is action;

##### Sample

    do useOwnChallenge;

#### action backupOwnKeys

Make a backup of all Own Keys.

#### action disable

Diable Sync and shut down the State Machine.

#### action newChallengeAndNegotiationBase

A new Challenge and a new Response will be computed randomly. Both are copied
into the I/O Buffer. The Negotiation Base is being computed randomly.

#### action openNegotiation

Key and Identity of the partner are being cleared. The Negotiation ID is being
calculated by the Negotiation Base XOR the Challenge of the partner.

#### action ownKeysAreDefaultKeys

Flag Default Keys of Own Identities as Group Keys.

#### action prepareOwnKeys

Write list of Own Identities into the I/O Buffer and load list of Own Keys into
the Device state.

#### action prepareOwnKeysFromBackup

Restore the formerly backed up Own Keys into the I/O Buffer.

#### action receivedKeysAreDefaultKeys

Set the received Own Keys as Default Keys for the Own Identities.

#### action resetOwnGroupedKeys

Do a KeyReset on Own Group Keys.

#### action resetOwnKeysUngrouped

Do a KeyReset on all Own Keys.

#### action saveGroupKeys

Load Own Identities from the I/O Buffer and store them as Own Identities.

#### action showBeingInGroup

Signal `SYNC_NOTIFY_IN_GROUP` to the App.

#### action showBeingSole

Signal `SYNC_NOTIFY_SOLE` to the App.

#### action showDeviceAccepted

Signal `SYNC_NOTIFY_ACCEPTED_DEVICE_ACCEPTED` to the App.

#### action showDeviceAdded

Signal `SYNC_NOTIFY_ACCEPTED_DEVICE_ADDED` to the App.

#### action showJoinGroupHandshake

Signal `SYNC_NOTIFY_INIT_ADD_OUR_DEVICE` to the App.

#### action showGroupCreated

Signal `SYNC_NOTIFY_ACCEPTED_GROUP_CREATED` to the App.

#### action showGroupedHandshake

Signal `SYNC_NOTIFY_INIT_ADD_OTHER_DEVICE` to the App.

#### action showSoleHandshake

Signal `SYNC_NOTIFY_INIT_FORM_GROUP` to the App.

#### action storeNegotiation

The Negotiation in the I/O Buffer is being stored for the Device. The Sender
FPR and partner's Identity are both stored for later comparison.

#### action storeThisKey

Load the Sender Key of the partner from the I/O Buffer and store it for later
use.

#### action tellWeAreGrouped

Set the `is_grouped` Field in the I/O Buffer to true.

#### action tellWeAreNotGrouped

Set the `is_grouped` Field in the I/O Buffer to false.

#### action trustThisKey

Trust the formerly stored Key of the partner. Load this Key into the I/O
Buffer.

#### action untrustThisKey

Revoke Trust from the formerly stored Key of the partner. Clear the Key in the
I/O Buffer.

#### action useOwnChallenge

The Challenge of the Device is being copied into the I/O Buffer.

#### action useOwnResponse

The Response of the Device is being copied into the I/O Buffer.

#### action useThisKey

Copy the stored Sender Key of the partner into the I/O Buffer.

## Use Cases

### Device Discovery

If there is more than one Device using the same Sync Channel (i.e. the same
Inbox in one or more Accounts, respectively) then p≡p Sync is there to detect
the other Devices. Therefore, a Device, which is in state Sole, is sending a
Beacon Message, so it can be detected by a second Sole Device or by Devices,
which are already forming a Device Group.

#### Relating Beacons

To make it distinguishable, which Device is sending which Beacon, Beacons have
the Field `challenge`. This field is of type `TID` (transaction ID), which is
defined as UUID version 4 variant 1: a completely random UUID (see
`pEpEngine/asn.1/pEp.asn1`).

The `challenge` is initialized with new random data whenever one of the two
Stable States (Sole or Grouped) are being reached. It is a pseudonym for the
Device. The initialization takes place by executing the Action
`newChallengeAndNegotiationBase`.

#### The Handshake

By reading a Beacon, which does not deliver the own `challenge`, a Device can
learn of a new other Device. Beacons are then answered with a
NegotiationRequest Message. This message is repeating the Beacon's `challenge`
and adding an own `response`, which is again a randomly chosen `TID`, and again
a pseudonym. Own NegotiationRequest Messages can be identified and ignored by
the value of the `response`. Additionally, a suggestion for a transaction ID
for a `negotiation` about forming a Device Group or joining an existing Device
group is being sent, together with the field `is_group` to determine between
the two cases.

When reading the NegotiationRequest of another Device, which is repeating the
own `challenge` a Device learns that it was detected by another Device. It then
is answering with a NegotiationOpen Message by repeating the `response`
pseudonym of the other device and the transaction ID for the `negotiation` to
signal that it is aware of the other Device and ready to execute the
`negotiation` process.

The three messages Beacon, NegotiationRequest and NegotiationOpen are
fulfilling the pattern of a [three way
handshake](https://en.wikipedia.org/wiki/Handshaking). At the same time
NegotiationOpen is opening a [distributed
transaction](https://en.wikipedia.org/wiki/Distributed_transaction), the
Negotiation.

### Forming a Device Group by two Sole Devices

In case there is no Device Group existing yet, then two Sole devices can form
one. There is an extra problem then: the symmetry of the situation. Which
Device does have the role of sending out Beacons and which has the role of
answerng with a NegotiationRequest Message? This must be decided first. Hence
there are two roles a Device can go into: the Offerer, who is sending the
Beacon, and the Requester, who is answering with a NegotiationRequest Message.

#### Deciding Roles

Both Devices have to decide their role independently from each other, and it
must be guaranteed that the decision is correspondent on both sides,
respectively.

To make this possible the criterion to decide whether a Device is Offerer or
Requester there is the Condition `weAreOfferer`. The Device is Offerer if the
`challenge` of the other Device is greater than its own `challenge`, otherwise
it is Requester.

The decision is being made on a Beacon Message arriving. Then the Device is
knowing both Challenge TIDs.

#### Starting the Negotiation as Offerer

If the Device is Offerer and it gets a Beacon it may be the case that the
former own Beacon timed out so the other Device couldn’t see it. Hence another
Beacon is sent out to make sure the other Device can see that we’re Offerer.

Being Offerer the Device is waiting for a NegotiationRequest coming from the
Requester. When a NegotiationRequest is arriving the Device is checking if the
own `challenge` was repeated. By doing so it is checking if the Requester is
authenticated and can read the Channel. In case it is storing the `negotiation`
TID for further use. From then on it is basing its communication on this TID
while it is in this Negotiation. It tells this to the other Device by sending
the NegotiationOpen Message repeating the `response`. There is no Action to
repeat the `response`, because repeating what is in the I/O Buffer is the
default. Then it is transitioning to the State HandshakingOfferer, which is a
Transitional State to start the Handshake process.

#### Starting the Negotiation as Requester

If the Device is Sole and Requester the flag `is_grouped` is cleared in the I/O
Buffer by executing `tellWeAreNotGrouped` to signal its Sole State to the
Offerer. Executing `useOwnResponse` is copying the own Response TID into the
I/O Buffer.

Executing the Action `openNegotiation` is calculating the Negotiation TID as
Challenge of the other Device XOR Negotiation Base. By doing so each possible
partner is having its own Negotiation ID in case multiple Sole Devices are
active at the same time. Then the Message NegotiationRequest is being sent out.

After sending the NegotiationRequest the value of the `challenge` in the I/O
Buffer is reverted to the own Challenge TID to answer other Beacons, which may
arrive from other Devices.

The Requester is then waiting for the NegotiationOpen Message from the Offerer.
It is checking if the `response` was correctly repeated. By doing so it is
checking if the Offerer is authenticated and can read the Channel. The
Requester is storing the `negotiation` TID for further use. The Device is
transitioning to the Transitional State HandshakingRequester to start the
Handshake process.

#### Handshaking with two Sole Devices

Each Device is waiting for two Events, which both must happen: the User
must Accept the Handshake on the Offerer Device and the User must Accept the
Handshake on the Requester Device. Only if both Accepts where received the
Handshake is accpeted. 

The Offerer is sending the Message CommitAcceptOfferer in case it gets
signalled Accept from the User, so the Requester gets informed about this.
Accordingly, the Requester is sending CommitAcceptRequester in case it is
getting signalled Accept from its User.

The sending of CommitAcceptOfferer and CommitAcceptRequester are not arbitrary
in sequence, though. To keep the wanted asymmetry the Offerer is only sending
CommitAcceptOfferer after it was receiving CommitAcceptRequester AND it was
signalled the Accept Event by the User. The Requester is sending
CommitAcceptRequester immediately after it got signalled the Accept Event from
the User. As a result the CommitAcceptRequester Message is always sent before
the CommitAcceptOfferer is being sent.

The Negotiation is considered committed with result Accept if and only if both
Commit Messages where received. This is fulfilling the pattern of the
[Two-phase commit
protocol](https://en.wikipedia.org/wiki/Two-phase_commit_protocol).

#### In case of Reject or Cancel

If the User selects Reject on Offerer or Requester, then the CommitReject
Message is being sent and p≡p Sync is being disabled.  If the CommitReject
Message is received because the User selected Reject on the other Device, p≡p
Sync is disabled, too.

The Negotiation is considered committed with result Reject if Offerer OR
Requester sent CommitReject. This is a derivate of the Two-phase commit
protocol.

In case the User selects Cancel then the Rollback Message is being sent, and
the Device is transitioned to State Sole. The Negotiation is then cancelled,
but a next Negotiation can happen after this.  In case a Rollback Message is
being received then the Device is transitioned to State Sole. The Negotiation
is then cancelled, but a next Negotiation can happen after this.

The Rollback is fulfilling the pattern of the Two-phase commit protocol.

### Joining an already existing Device Group

### Sharing of Own Identities and Own Keys in a Device Group

