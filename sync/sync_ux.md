# p≡p Sync UX

Sync is a protocol to form one device group. It first is driving a
transaction named the Negotiation. There are two situations Sync can be
in:

1. either there is no device group yet
2. or there is already a device group

## Case 1):

In case 1) we have two devices in the state Sole. When the user
configures the first device, nothing happens. When the user configures
the second device, it will detect that there is another device being in
state Sole.

The two devices detect each other. Both are showing a dialog asking the
user: “There is another device detected. Shell we form a device group?”

There are three possible answers:

1. Accept
1. Reject
1. Cancel

If one of the devices gets a Cancel, then the device group is NOT
formed. Sync remains enabled on both devices. This is corresponding with
a ROLLBACK of the Negotiation.

If one of the devices gets a Reject, then the device group is NOT
formed. Sync then is disabled on both devices. This is corresponding
with a COMMIT of the Negotiation with the result REJECT.

If both devices get an Accept, then the device group is formed. Sync is
then enabled on both devices. This is corresponding with a two-phase
COMMIT of the Negotiation with the result ACCEPT.

## Case 2):

In case 2) we have at least two devices forming a device group already
(named “old devices”), being in state Grouped. And we have one device,
which is not yet in a device group (named “new device”), being in state
Sole.

The new device and the old devices detect that there is a new device,
which could join the existing device group. The new device is showing
a dialog with “There is already a device group. Shell this device join?”
Possible answers are Join/Accept, Reject and Cancel. The old devices are
ALL showing a dialog with “A new device is detected. Shell we accept
the new device as new member in our device group?” Possible answers are
Accept, Reject and Cancel.

If one of the devices gets a Cancel, then the new device is NOT added to
the device group. Sync remains enabled on all devices. This is
corresponding with a ROLLBACK of the Negotiation.

If one of the devices gets a Reject, then the new device is NOT added to
the device group. Sync remains enabled on the old devices, but gets
disabled on the new device. This is corresponding with a COMMIT of the
Negotiation with the result REJECT.

Only if the new device gets an Accept and at least one of the old
devices gets an Accept, then the new device is added to the device group.
Sync then remains enabled on the old devices, and gets enabled on the
new device. This is corresponding with a COMMIT of the Negotiation with
the result ACCEPT.

Key sync is starting while Sync is taking place. The Sync dialog is a
Trustwords dialog offering Trustwords to check for the user. User's
decision is not only based on if she/he wants to have a device group in
case 1) – or – if she/he wants to add a new device to an existing device
group in case 2), but also on the question, if the Trustwords on the
two handled devices (either the two Sole ones or the new one and one of
the old ones) are identical.

Because there is a Trustwords check, from then on the connection is
becoming green, and secret keys will be sent and shared on all devices
being member of the same device group.

When Sync is switched off on a device, then it leaves the device group
it is in. A Key reset is needed then on the remaining devices, dealing
out new group keys for all own identities.

Sync can be switched on in two ways:

1. Switched on for all (default in p≡p apps)
2. Switched on only for a list of accounts (reached by switching it off
   first)

If Sync is enabled in 1) then adding a new account will have Sync for
this account, too, implicitely.

If Sync is enabled in 2) then adding a new account will have Sync
switched off for this account by default.
