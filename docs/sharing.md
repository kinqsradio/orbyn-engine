# Sharing lists and projects

This is the design for phase 4: sharing a list or a project with other people, the way a shared Reminders list works at Apple. It is not built yet. It depends on the key service's transparency log ([key-service.md](key-service.md)), so it comes after that.

## The caller and the goal

Maya shares Groceries with Sam, who can edit it.

- Sam's phone and laptop see the list and its changes at once.
- When Maya removes Sam, Sam's devices keep what they already had and see nothing written afterwards.
- A server that lies, even one working with a participant, cannot:
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

### Statements

The public halves are published as **account key statements**, `orbyn/account-key-statement/v1`. Each one is length-prefixed over:
- the account id;
- both public keys;
- a sequence and prev (the hash of the previous statement).

Each statement is signed twice:
- **by the account key itself**, the new key for the first statement and the previous key for a continuation, so a statement proves possession and continuity;
- **by a trusted device of the account**, so the account's own approval chains vouch for it.

### Logging

Every statement is appended to the transparency log under that account's map key. `GET /v1/accounts/{id}/key` returns the head, its chain and a fresh, cosigned lookup proof.

**Before Maya's device seals anything to Sam**, it requires all three:
- a lookup proof no older than 24 hours;
- a chain that verifies;
- a head no older than the head it pinned for Sam (see *Contacts*).

**Sam's own devices** check the log for their account. A statement they did not make, or that no device of Sam's account made, is shown as a possible takeover, with the same checks as for recovery entries.

### Contacts

- **Pinning.** For every account it has shared with, a device pins the highest sequence and statement hash it accepted. It refuses a lower sequence or a different hash at the same sequence.
- **Continuations.** A new statement signed by the previous account key is accepted on its own.
- **Resets.** A new statement that the previous key did not sign is accepted only as described under *Recovery*.

### Verifying a person

- **Default: logged, unverified.** The share sheet shows the person as unverified until both people compare safety codes. The key is still logged and cosigned, so substituting it is detectable by Sam's own devices, which is not the case for a key that is merely server-vouched.
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
  - the full set of (account id, account key statement hash, role);
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
- the version is newer than the device's copy and sealed under the current key, or under a key that was current for that statement.

A demoted or removed member therefore cannot write, even with old keys and a cooperating server: their versions under the old key are older than the rotation, and under the new key they hold nothing.

## Keys for a shared zone

- **Sealing.** Only the owner's devices seal zone keys to another account: the `account` envelope suite `orbyn/wrap-account/v1`, following the P-256 suite's pattern in key-service.md but with X25519. It has:
  - its own HKDF info, AEAD context and signature context;
  - a fully length-prefixed transcript binding the owner account, the zone, the key id, the recipient account and the hash of the recipient's account-key statement;
  - a signature by the owner's account key.

  Members' devices accept zone keys only in this form, from the owner. A viewer or a server cannot plant a "first key".
- **Rotations** are signed by the owner's account key, and bind:
  - the new and previous key ids;
  - the participant statement hash;
  - the zone version at which it took effect.
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
- **The window.** Between a leave (or a removal made while the owner's devices are offline) and the next rotation, a server that kept serving the leaver new ciphertext could let them read it. The window is bounded only by the owner being online. Members see "Waiting for Maya to secure this list" until the rotation arrives. Editors cannot rotate in v1, which keeps one key authority.
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

- **Deleting a shared zone** is owner-only, with a tombstone signed by the owner's account key, `orbyn/zone-delete/v1`.
- **Members' devices** remove it and keep nothing synced. The local copy goes to the trash for 30 days, as for any deleted list.
- **Deleting the owner's account** deletes the owner's shared zones the same way, with members told: "Maya deleted her account; Groceries is gone".

## What the server still sees

The threat model gains:
- the social graph: who shares with whom, and roles;
- which account wrote each version, from the signatures;
- invitation timing, under keyed, expiring email digests;
- the owner's device ids in cross-account notices.

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
- **The key service handing out shared zone keys.** It would make shared zones readable by the key service even when end-to-end, and tie sharing to the key service being up.
- **A server-vouched account key.** The record server could substitute keys undetectably. Logging with cosigned lookup proofs makes substitution visible to the account's own devices.
- **Escrowing the account key.** Recovery would then silently restore every share to whoever recovered the account. A reset that owners must confirm is safer.
