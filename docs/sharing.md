# Sharing lists and projects

This is the design for phase 4: sharing a list or a project with other people, the way a shared Reminders list works at Apple. It is not built yet. It depends on the key service's transparency log ([key-service.md](key-service.md)), so it comes after that.

## The caller and the goal

Maya shares Groceries with Sam, who can edit it.

- Sam's phone and laptop see the list and its changes at once.
- When Maya removes Sam, Sam's devices keep what they already had and see nothing written afterwards.
- A server that lies, even one working with a participant, cannot do the following, except during the stated owner-offline window after someone leaves (see *Removal, leaving and the window*):
  - read a shared list;
  - add itself or anyone else as a member;
  - write as someone else;
  - let a viewer write;
  - make a member's devices escrow keys they should not.
- What it can do is withhold or delay, and devices detect that where the design says so.

## What already exists

- **Zones and keys.** Every list, project and calendar is a zone with an owner account. Records are sealed with record keys, which are sealed with the zone key.
- **Key envelopes.** Device envelopes are sealed to a device's X25519 key and signed by the sending device. A device accepts envelopes only from devices it verifies through approval chains inside its own account.
- **The transparency log.** The key service keeps a witness-cosigned log with per-account lookup proofs (see key-service.md). Sharing logs account keys in it.
- **Participants table.** `zone_participants` exists in the store and is unused.

## Account keys

Each account has one **account key pair**: Ed25519 for signing and X25519 for receiving.

### Making and holding it

- The account's first trusted device makes the pair after sign-up and verification.
- It reaches the account's other trusted devices through the keychain, in an envelope labelled `orbyn/account-key/v1`. The label binds the statement's sequence and hash, so a server cannot feed a new device an old key. The receiving device checks that the public key it derives equals the head it verified.
- **The account key is never escrowed** to the key service. Account recovery therefore does not restore it (see *Recovery*).
- **Removing a device rotates it.** When a device is removed, a remaining trusted device makes a new account key pair. It publishes it as a continuation signed by the old key, and seals the private half only to the remaining devices. A removed or stolen device therefore holds only keys that are being retired.

### Statements

The public halves are published as **identity statements**, `orbyn/identity-statement/v1`. Each one is length-prefixed over:
- the normalised email;
- the account id;
- both public keys;
- a sequence and prev (the hash of the previous statement);
- for a reset, the hash of the recovery-finish log entry it follows.

Each statement is signed twice:
- **by the account key**: the new key for the first statement and for a reset, the previous key for a continuation;
- **by a trusted device of the account**, so the account's own approval chains vouch for it.

### Logging

Identities are logged by **email**, the identity people share with, as key-transparency systems for messaging do.

- **The identity map.** The key service keeps a second verifiable map in the same witness-cosigned log, separate from the service-key map in key-service.md.
  - Its map key is `VRF(normalised email)`: ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381) under a VRF key held by the key service.
  - The VRF lets anyone who knows an email find and verify its entry and its proof, but does not let the key service's readers walk the list of emails.
  - The VRF key is stored wrapped under the HSM key-encryption key. It is not an HSM operation, because HSMs do not offer VRFs. A leak of it exposes only which emails have entries, not keys or contents.
- **Accounts without a service key.** The identity map is independent of the service key and of the protection level. Advanced accounts use it the same way.
- **Self-hosting.** Self-hosts without a key service have no log, so they cannot share.
- **Proving the email.** The key service appends a **first statement** for an email only after proving the submitter controls it.
  - It sends its own six-digit code to that email, through its own mail path, not the record server's.
  - The device submits the code with the statement.
  - The code follows engine#30's rules: one active code per email, mail caps per address, and guess caps per code and per IP prefix.
- **One chain per email.** A first statement for an email that already has a chain is refused. The only way to replace it is a reset for the same account (see *Recovery*).
- **Changing an email** is a signed **move**: a statement under the old email naming the new one, plus a first statement under the new email, proven like any first statement. Both are logged, and contacts follow the move.
- **Deleting an account** logs a tombstone under its email, signed by the account key. A later first statement for that email needs the email proven again.
- **Fresh first statements wait.** Contacts do not seal to a first statement until a cosigned head has included it for 24 hours. This is a margin on top of the email proof: if a proof was ever passed on wrongly, the email's owner has a day to see the new identity before anyone seals to it.
- **Submitting.** A device submits a statement with `POST /v1/identity/statements`. The key service checks both signatures and the chain, the email proof for a first statement, and the recovery-finish link for a reset, before appending.
- **Lookup is not public.** `GET /v1/identity/{email}` is answered by the key service, but only with a **lookup capability**.
  - The record server issues a capability only for an **accepted invitation**, bound to the inviter's account, the zone and the email digest, and for an account's **own email**, to its own sessions.
  - It is signed by the record server with a key the key service pins, and it expires after 10 minutes.
  - There is no lookup for an email the caller has not invited and had accepted, so the identity map is never an "is this email registered" oracle.
  - Lookups are limited per session and per address, and the answers for a missing entry and a present one have the same shape and timing (a non-membership proof).
  - Both servers still learn whether an email has an entry when a lookup is made, and the metadata section says so.
- **The answer** is the VRF output and proof, the head statement with its chain, and a cosigned lookup proof. Clients verify the VRF proof per RFC 9381, against a VRF public key pinned and versioned in client configuration like the identity keys.
- **Before sealing.** Before Maya's device seals anything to Sam, it requires:
  - the email Maya typed, looked up by her own device with the capability for Sam's accepted invitation;
  - a lookup proof from a cosigned head no more than 2 hours old by the witness's signed time (the monitoring bound in key-service.md; the 24-hour margins below are a separate rule about how long a statement has been in the log);
  - a chain that verifies;
  - a head no older than the one she pinned for that email.
- **Monitoring.** Sam's own devices look up Sam's own email on every log check. Any statement for Sam's email that no device of Sam's account made, including one from another account claiming sam@, is shown as a possible takeover.

### Contacts

- **Pinning.** For every email it has shared with, a device pins the account id, the highest sequence and the statement hash it accepted. It refuses a lower sequence, a different hash at the same sequence, or a different account id for the email (except a reset, below).
- **Continuations take time to count.** A continuation (signed by the previous key) is used for sealing only once:
  - a cosigned head has included it for **24 hours**;
  - no other statement exists at the same sequence.

  This gives Sam's devices a day to see a continuation they did not make and publish a competing one.
- **Two statements at one sequence** freeze sealing to that email on every contact's devices, and prompt: "Sam's identity changed in two ways. Compare safety numbers with Sam." Sealing resumes only for the statement the person confirms by safety number.
- **Resets** are accepted only as described under *Recovery*.

### Verifying a person

- **Default: logged, unverified.** The share sheet shows the person as unverified until both people compare safety numbers. The identity is logged and cosigned under the email Maya typed, so a substitute, including another account claiming Sam's email, is visible to Sam's own devices. An unverified share therefore trusts the log to be watched by Sam's devices, not the record server's word.
- **End-to-end zones require verification.** A zone whose statement says `end-to-end` can be shared only with verified people.
- **Verified.**
  - Maya and Sam compare a **safety number**: 60 digits, or a QR code scanned in person, computed under `orbyn/safety-code/v1` over both account ids and both account keys in a canonical order.
  - It is the full fingerprint, so it cannot be ground offline.
  - Marking it verified pins that key. Any later reset, as opposed to a continuation, drops Sam back to unverified with a warning.

## Roles and the participant set

- **Roles in v1.**
  - There is exactly one **owner**, the zone's account, plus **editors** and **viewers**.
  - Only the owner seals keys to accounts, rotates the zone key, changes membership or roles, and deletes the zone.
  - Editors write records; viewers read.
  - There is no second owner and no ownership transfer in v1.
- **The participant statement.** Membership is a chain, `orbyn/zone-participants/v1`, **signed by the owner's account key**. Each statement is length-prefixed over:
  - the owner account and the zone;
  - a sequence and prev;
  - the full set of (account id, email, identity statement hash, role);
  - the zone's protection level (`standard` or `end-to-end`).

  The server stores it and serves it with the zone. It is capped at 1000 statements per zone, and uploads are limited to 30 an hour per zone, counted after the signature verifies. At the cap the owner can still remove people, by compacting the chain to a checkpoint statement the owner signs; it is never a lockout.
- **Anchoring.** Every zone-key rotation (see below) binds the hash of the participant statement it was made for. A device accepts a statement only if:
  - it is at least as new as the one bound by the newest key it holds;
  - the head the server serves is not older than that.

  So the head cannot be stripped or rolled back the way engine#32's endorsement could be. A device that joins bootstraps from the statement bound by the first key it is given.
- **Server enforcement** is the first layer: viewers get `zone_read_only` on uploads, and non-owners get `zone_owner_only` on membership, rotation and key routes. Devices then check everything themselves, as below.

## Records in shared zones

The zone key alone cannot tell who wrote a record, because every member, viewers included, holds it. So in a shared zone, every record version and tombstone is also signed by its author's **account key**: `orbyn/shared-record/v1`, length-prefixed over:
- the owner account and the zone;
- the record id, its type and base version;
- the zone key id;
- the hash of the ciphertext and of the wrapped record key.

A device accepts a version only if all of these hold:
- its signature verifies against the author's pinned account key;
- the author has a role that may write in the participant statement bound by the zone key the version is sealed under;
- it is sealed under the zone's current key, or it is history proven by a rotation, as below.

**Rotations seal history.** An owner's rotation away from a key signs a Merkle root over every version accepted under that key. A record version's leaf is (record id, version, hash of the ciphertext and of the wrapped record key). A tombstone's leaf is (record id, version, hash of its signed delete proof), so tombstones are covered and proven the same way. This is the per-zone signed version log that architecture.md lists as open, built here for shared zones.
- A device that already holds the zone refuses any newly arriving version under a retired key, whatever its version number, because version numbers are server-assigned and unsigned.
- A device that is **bootstrapping**, a new member or a new device, accepts an old-key version only with an inclusion proof against the root its rotation commits to. History is therefore readable, but nothing can be added to it after the rotation.

A demoted or removed member therefore cannot write, even with old keys and a cooperating server: a new version under the old key is refused, and they hold nothing under the new key. A member who wrote offline under the old key seals the write again under the new key before uploading it.

## Keys for a shared zone

- **Sealing.** Only the owner's devices seal zone keys to another account: the `account` envelope suite `orbyn/wrap-account/v1`, following the P-256 suite's pattern in key-service.md but with X25519. It has:
  - its own HKDF info, AEAD context and signature context;
  - a fully length-prefixed transcript binding the owner account, the zone, the key id, the recipient account and the hash of the recipient's identity statement;
  - a signature by the owner's account key.

  Members' devices accept zone keys only in this form, from the owner. A viewer or a server cannot plant a "first key".
- **Rotations** are signed by the owner's account key, and bind:
  - the new and previous key ids;
  - the participant statement hash;
  - the zone version at which it took effect;
  - the Merkle root over the retired key's accepted versions (see *Rotations seal history*), so the root is signed by the owner and the server cannot swap it.
- **Escrow.** Only the owner's devices write service envelopes for a shared zone, and only when the participant statement says `standard`. The server refuses a service envelope for a zone that the session's account does not own. A participant's recovery therefore never exposes someone else's zone.

## Protection level of a shared zone

The owner sets it in the participant statement.

- **End-to-end** is allowed only while every participant's own verified protection setting is Advanced. Each participant's device checks its own verified level (engine#32) against the statement, and refuses to stay in an end-to-end zone while it is not Advanced, telling the person why.
- **Standard** otherwise, said plainly in the share sheet.
- **A downgrade** from end-to-end to Standard is a new owner-signed statement, shown to every member, never a server decision.

## Removal, leaving and the window

- **Removal is one batch** from an owner device, accepted all or nothing:
  - the new participant statement;
  - the rotation bound to it;
  - new account envelopes for the remaining members only.

  The server drops the removed account at once, and its next fetch answers `zone_not_found`.
- **Leaving** is a statement signed by the member's own account key, `orbyn/zone-leave/v1`. The server drops the member at once.
  - Members' devices stop accepting the leaver's writes as soon as they see the leave statement.
  - The owner's next device online rotates the key.
- **The window.** After a leave, until the owner's next device online rotates the key, a server that kept serving the leaver could let them read anything sealed under the old key. So members **hold their own uploads** for that zone, showing "Waiting for Maya to secure this list", until the rotation arrives. Nothing new is sealed under a key the leaver holds. The window is bounded only by the owner being online. Editors cannot rotate in v1, which keeps one key authority.
- **What removed people keep.** Their devices keep the local copy of what they had; nothing pretends otherwise. They mark the list "You were removed" and stop syncing it.

## Recovery and key changes

- **A participant recovers their account.** Sam recovers through Standard recovery. The account key is not escrowed, so Sam's recovered account makes a new key with a statement not signed by the old key: a **reset**.
  - The reset is accepted only when the transparency log shows a recovery-finish entry for Sam's account linked to it.
  - Owners' devices then **never re-wrap automatically**. They prompt: "Sam's account was recovered. Share Groceries with Sam again?"
  - A verified Sam drops back to unverified.
- **An owner recovers their account.** Maya recovers her own zones through the key service, as for any Standard zone, but her new account key is a reset. Members see "Maya's account was recovered", and Maya re-signs the participant statement with the new key. Members accept that only after the same linked log entry and a prompt.
- **Every account-key change** is shown to the people the account shares with: a continuation as a quiet note, a reset as a prompt.

## Invitations

These follow engine#30's rules for addresses.

- **One answer.** Inviting answers the same whether or not the email has an account.
- **Storage.** One pending invitation per (zone, email digest), and digests expire with the invitation after 30 days.
- **Caps.** One keyed counter per invitee address caps mails at 5 a day across all inviters, plus 20 invitations an hour per inviter. The answers are identical at the caps, and the mail is sent asynchronously on both paths.
- **The mail.** It shows the inviter's verified email and the list name, escaped and truncated, with "Block invitations from this person". A blocked inviter's later invitations to that address are dropped silently.
- **Accepting.** It needs a session whose account's verified email matches the invitation. Before sealing, the owner's device shows the accepting account's key fingerprint and its verification state.

## Deleting

- **Deleting a shared zone** is owner-only, with a tombstone signed by the owner's account key, `orbyn/shared-zone-delete/v1` (distinct from the device context `orbyn/zone-delete/v1`).
- **Members' devices** remove it and keep nothing synced. The local copy goes to the trash for 30 days, as for any deleted list.
- **Deleting the owner's account** deletes the owner's shared zones the same way, with members told: "Maya deleted her account; Groceries is gone".

## What the server still sees

The threat model gains:
- the social graph: who shares with whom, and roles;
- which account wrote each version, from the signatures;
- invitation timing, under keyed, expiring email digests;
- the owner's device ids in cross-account notices;
- identity lookups: the key service sees which emails a device looks up, and when, and both servers learn whether an email has an entry when an accepted invitation's lookup is made.

Contents stay sealed.

## Limits

- 50 participants per zone.
- 100 shared zones per account.
- Participant statements: 1000 per zone, then checkpoint compaction, at 30 an hour.
- Account key statements: 30 a day.
- Invitations: as above.

## Order of work

1. The key service's transparency log, from key-service.md step 3.
2. Account keys:
   - making the pair and its keychain envelope, bound to the statement;
   - double-signed statements, logged with lookup proofs;
   - contact pinning, continuation and reset rules.
3. The participant chain signed by the owner's account key, server roles, the anchoring through rotations, and the protection level in the statement.
4. Signed shared records and tombstones, and device-side author checks.
5. The `orbyn/wrap-account/v1` envelopes, accepting invitations, the owner-only escrow rule, and fetch and upload across accounts.
6. Removal as one batch, leave statements, zone deletion, and the recovery prompts.
7. Planner:
   - the share sheet (role, verification state, safety number and QR);
   - invitations;
   - the waiting and removed states;
   - key-change prompts;
   - shared-change notifications.

Each step ships in both repos behind the same contracts.

## Rejected alternatives

- **Sealing zone keys to each participant device.** The owner would have to verify another account's device approval chains, and every new device of Sam's would need the owner online. The account key moves that into Sam's own account.
- **The key service handing out shared zone keys.** It would make shared zones readable by the key service even when end-to-end. Sharing does depend on the key service's log for lookups, but never gives it keys.
- **A server-vouched account key, or a log keyed by account id.** The record server could substitute keys, or the account an email belongs to, undetectably. A log keyed by the email the inviter types, which the email's own devices watch, makes either visible.
- **Escrowing the account key.** Recovery would then silently restore every share to whoever recovered the account. A reset that owners must confirm is safer.
