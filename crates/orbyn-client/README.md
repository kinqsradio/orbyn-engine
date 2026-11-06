# orbyn-client

The device sync engine. It keeps a device's cache of records per zone, encrypts each record with its own key under the zone key, builds atomic uploads, merges conflicts and incoming changes with `orbyn-sync`, and hands zone keys to other trusted devices as signed envelopes. It does no IO: the host makes the HTTP calls, stores the snapshot and passes in the clock. Pure Rust, so it builds for WebAssembly; `orbyn-wasm` wraps it for JavaScript.
