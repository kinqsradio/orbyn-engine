# orbyn-auth-client

The OPAQUE (RFC 9807) ciphersuite Orbyn uses, and the device side of sign-up and sign-in: the password never leaves the device. It also builds the messages a device signs to prove it holds its keys and to approve another device. Runs on devices, including the web as WebAssembly; `orbyn-core` uses its `Suite` for the server half.
