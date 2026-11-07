# Sharing lists and projects

This is the design for phase 4: sharing a list or a project with other people, the way a shared Reminders list works at Apple. It is not built yet.

## The caller and the failure

Maya shares Groceries with Sam, who can edit it.

- Sam's phone and laptop see the list and its changes at once.
- When Maya removes Sam, Sam's devices keep what they already had, but see nothing written afterwards.
- A server that lies cannot add itself to the list, read a change, or let a viewer write.

## What already exists

- **Zones and keys.** Every list, project and calendar is a zone with an owner account. Its records are sealed with record keys, which are sealed with the zone key.
- **Key envelopes.** A zone key reaches another device only through an envelope sealed to that device's X25519 key and signed by the sender's Ed25519 key. A device accepts envelopes only from devices it verifies through approval chains inside its own account.
- **Participants table.** `zone_participants` exists in the store and is unused. Today another account's request answers `zone_not_found`.

Sharing therefore needs three things that do not exist:
- an identity for an account, not just a device, that another account can encrypt to and verify;
- participants with roles that the server enforces and devices check;
- removal that keeps a removed participant out of new data.

## Account keys

Each account gets one **account key pair**:
- Ed25519 for signing;
- X25519 for receiving keys from other accounts.

**Creation and holding.**
- The account's first trusted device makes the pair after sign-up and verification.
- It reaches the account's other devices through the keychain, like a zone key: an envelope sealed to each verified device, under the label `orbyn/account-key/v1`.
- Only the account's trusted devices hold the private halves.

**Publishing.** The public halves are published as an **account key statement**, `orbyn/account-key-statement/v1`, over the account id, both public keys and a sequence. It is signed by a trusted device of the account and chained like the protection setting (seq, prev). `GET /v1/accounts/{id}/key` returns the newest statement and its chain.

**How another account trusts it.** There are two levels, as in messaging apps:
- **Server-vouched (the default).** Maya's device accepts the key the server returns for Sam's account, after checking the statement's signature chain within itself. It shows Sam's account key fingerprint in the share sheet.
- **Verified.** Maya and Sam compare a 12-digit safety code computed from both account keys, in person or on a call, and mark it verified. If the key ever changes after that, Maya's devices warn before sharing anything new with Sam.

Under Standard protection, server-vouched is the honest default: the server can already read Standard data. For Advanced protection's end-to-end sharing (phase 7), a server-vouched key is used, but the share sheet says the person is unverified until the safety code is compared.

**Rotation.** A device can rotate the account key: a new statement with the next sequence, and new envelopes to the account's devices. Other accounts see the new sequence on their next fetch. Their devices then re-wrap shared zone keys to the new key, and warn if that person was verified.

## Participants and roles

- **Roles:** `owner` (one, the zone's account), `editor` and `viewer`.
- **Inviting.** The owner invites by email.
  - `POST /v1/zones/{zone}/participants {email, role}` from a trusted device of the owner.
  - The answer is the same whether or not the email has an account. The invitation is stored against the email digest, and the email gets one message: "Maya shared Groceries with you on Orbyn". A person without an account can sign up with that email and then accept. An invitation never tells the owner whether an email has an account.
  - Unaccepted invitations expire after 30 days. The owner sees them as "Invited" either way.
- **Accepting.** The invitee's device accepts: `POST /v1/invitations/{id}/accept`, from a trusted device of the invitee.
- **Server enforcement.**
  - Viewers can read the zone and its changes but get `zone_read_only` on any upload.
  - Editors can upload records.
  - Only the owner can invite, change roles, remove participants, rotate the zone key or delete the zone.
  - A participant can leave on their own.
- **The participant set is signed.** Every change to it is a **participant statement**, `orbyn/zone-participants/v1`, signed by an owner's device, over:
  - the zone, the sequence and prev;
  - the full set of (account id, account key fingerprint, role).

  The server stores the chain and serves it with the zone.
- **Device checks.** A participant's device:
  - verifies the chain from the owner's account key;
  - accepts an envelope for the shared zone only from a member account;
  - treats a record or tombstone as valid only if its author is in the set with a role that may write.

  So a server that invents a participant, or upgrades a viewer, is caught by every device, not only by the server's own check.

## Keys for a shared zone

- **Getting the key to Sam.** When Sam accepts, one of Maya's devices seals the zone's keys to Sam's account X25519 key: an envelope with recipient kind `account`, under the label `orbyn/shared-zone-key/v1`, binding the zone, the key id and Sam's account id. It is signed by Maya's account Ed25519 key.
- **Sam's devices.** They open it with the account key they hold, then keep the zone key as they keep their own.
- **Records.** They stay sealed exactly as today: record keys under the zone key. The author is now carried as the author account's key fingerprint with the device id, and signed deletes are signed by the author account's key.
- **Storage.** `key_envelopes` gains recipient kind `account`, alongside `device` and `service`.

## Removal

When Maya removes Sam:

1. One of Maya's devices writes a new participant statement without Sam.
2. It rotates the zone key, a new current key signed as a rotation as today.
3. It seals the new key only to the accounts still in the set.
4. The server drops Sam from the zone at once. Sam's next fetch answers `zone_not_found`, and his live connection is closed for that zone.

Sam's devices keep their local copy of what they already had: the server cannot take back what was shared, and nothing pretends otherwise. They mark the list "You were removed" and stop syncing it.

**Rotation follows the owner.** If Maya is offline when Sam leaves on his own, the server drops him immediately. Maya's next device to sync sees the new participant set and rotates the key then. Until it does, Sam could read new records if he still received ciphertext. He doesn't: the server stops serving him at once. The rotation closes the case of a server that keeps serving him.

## Standard and Advanced

- **Standard (v1).** Shared zones are Standard: the key service may hold a service envelope for the zone, as for the owner's own zones. That copy stays the owner's: recovery restores the zone keys to the owner's recovered account, not to other participants.
- **Advanced (phase 7).** A shared zone is end-to-end only when every participant's verified protection setting is Advanced: no service envelope is written, and the share sheet says so. Otherwise it stays Standard, and the share sheet says so too.

## Notifications

A change by another participant raises an in-app notification on the participant's devices: "Sam added Milk to Groceries". It is built on the device from the decrypted record. The server only says "this zone changed", as today.

## Limits

- 50 participants per zone.
- 100 shared zones per account, as owner or participant.
- 20 invitations per account an hour.

## Order of work

1. Account keys: making them, the keychain envelopes, the statement chain and its routes, and the client verification.
2. Participants: the routes, the server roles, the signed participant chain, and client verification of the chain and of record authors.
3. Shared-zone envelopes (recipient kind `account`), accepting an invitation, and fetch and upload across accounts.
4. Removal with rotation, and leaving.
5. Planner:
   - the share sheet (invite, role, fingerprint and safety code);
   - invitations;
   - the removed state;
   - notifications for shared changes.

Each step ships in both repos behind the same contracts.

## Rejected alternatives

- **Sealing the zone key to each of the participant's devices directly.** The owner's devices would need to verify another account's device approval chains, and every new device of Sam's would need the owner to be online. The account key moves that verification into Sam's own account, where approval chains already work.
- **Using the key service to hand out shared zone keys.** It would make every shared zone readable by the key service even when every participant is Advanced, and tie sharing to the key service being up.
