# orbyn-engine architecture

The plan lives in the [Orbyn platform plan](https://claude.ai/artifact/BBhxZSmXRg1DawhLVRbsNc). This file is the contract the code follows. Change it in the same commit as any rule it states.

## Rules

- Each device keeps the whole planner and works offline. The server is never the only copy of a person's work.
- Records are encrypted on the device before upload, at every protection level. The server stores ciphertext with a visible id, type, zone and version.
- Keys never go in the database or the logs. Only the key service unwraps a Standard-protection key, and every use is audited.
- Authorization is checked in the operation that does the work, not only in the route.
- Every external effect (a push, an email, a key rotation) has an operation identity, so a retry never duplicates it.
- Logs carry no content, keys or record payloads.
- One Docker image runs every server role, chosen by subcommand.
