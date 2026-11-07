//! The PKCS#11 implementation of [`Hsm`], through `cryptoki`: SoftHSM for development, CI and
//! self-hosting, or a cloud HSM's PKCS#11 module in production.
//!
//! - The **KEK** is a non-extractable, sensitive AES-256 token object (`orbyn-kek-v1`) that only
//!   wraps and unwraps.
//! - An **identity** is an Ed25519 key pair (`orbyn-identity-v<N>`), the private half a
//!   non-extractable, sensitive token object that only signs.
//! - An **account key** is a P-256 pair made as session objects, wrapped under the KEK with
//!   `CKM_AES_KEY_WRAP_PAD` (RFC 5649, the AES key wrap with padding the design calls KWP) and
//!   destroyed before the call returns. To use one it is unwrapped into a session object (not on the
//!   token, non-extractable) and used with `CKM_ECDH1_DERIVE` and `CKD_NULL`, the peer given as the
//!   uncompressed point of a validated [`P256Point`]; the derived value is read and destroyed.
//! - SoftHSM has no `CKM_HKDF_DERIVE`, so HKDF runs in the key service, in memory.
//!
//! Every key template sets every usage flag, true only for what the key is for.
//!
//! **Accepted limits.** The derived secret is read with `C_GetAttributeValue` through `cryptoki`,
//! which hands back a `Vec`; it is moved into a `Zeroizing` buffer at once, but the crate does not
//! expose the raw function list, so the read cannot go straight into a buffer of ours, and this
//! crate forbids `unsafe`. Copies `cryptoki` makes inside the call are not under our control; the
//! secret exists only for the one derive. **Required for production, not done on SoftHSM:** the KEK
//! should be marked `CKA_TRUSTED` by the Security Officer at `init`, and account keys created with
//! `CKA_WRAP_WITH_TRUSTED`, so that only the trusted KEK can wrap them. SoftHSM cannot do this
//! cleanly: the Security Officer cannot see the user's private objects, so it cannot set the
//! attribute on the KEK, and a key with `CKA_WRAP_WITH_TRUSTED` is refused by an untrusted KEK
//! (`CKR_KEY_NOT_WRAPPABLE`). A cloud HSM with an administrative role that can mark the key
//! should turn it on (see docs/key-service.md).

use crate::{Hsm, HsmError, HsmMessage, MessageKind, SessionKey, WrappedAccountKey};
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as CkError, RvError};
use cryptoki::mechanism::Mechanism;
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::mechanism::elliptic_curve::{EcKdf, Ecdh1DeriveParams};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use orbyn_crypto::P256Point;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use zeroize::Zeroizing;

/// DER of the P-256 curve OID, for `CKA_EC_PARAMS`.
const P256_PARAMS: [u8; 10] = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
/// DER of the Ed25519 OID (1.3.101.112), for `CKA_EC_PARAMS`.
const ED25519_PARAMS: [u8; 5] = [0x06, 0x03, 0x2b, 0x65, 0x70];
const KEK_LABEL: &[u8] = b"orbyn-kek-v1";

fn identity_label(version: u32) -> Vec<u8> {
    format!("orbyn-identity-v{version}").into_bytes()
}

/// The log key's label: a different set from the identities, so a version number alone cannot
/// reach the wrong key.
fn log_key_label(version: u32) -> Vec<u8> {
    format!("orbyn-log-v{version}").into_bytes()
}

/// What a key may be used for. Every template sets **every** usage flag, true only for what the
/// key is for, so nothing depends on a token's default (some default to true).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Use {
    Sign,
    Verify,
    SignRecover,
    VerifyRecover,
    Encrypt,
    Decrypt,
    Wrap,
    Unwrap,
    Derive,
}

fn on(allowed: &[Use], what: Use) -> bool {
    allowed.contains(&what)
}

/// The flags of a secret key.
fn secret_usage(allowed: &[Use]) -> Vec<Attribute> {
    vec![
        Attribute::Encrypt(on(allowed, Use::Encrypt)),
        Attribute::Decrypt(on(allowed, Use::Decrypt)),
        Attribute::Sign(on(allowed, Use::Sign)),
        Attribute::Verify(on(allowed, Use::Verify)),
        Attribute::Wrap(on(allowed, Use::Wrap)),
        Attribute::Unwrap(on(allowed, Use::Unwrap)),
        Attribute::Derive(on(allowed, Use::Derive)),
    ]
}

/// The flags of a private key.
fn private_usage(allowed: &[Use]) -> Vec<Attribute> {
    vec![
        Attribute::Decrypt(on(allowed, Use::Decrypt)),
        Attribute::Sign(on(allowed, Use::Sign)),
        Attribute::SignRecover(on(allowed, Use::SignRecover)),
        Attribute::Unwrap(on(allowed, Use::Unwrap)),
        Attribute::Derive(on(allowed, Use::Derive)),
    ]
}

/// The flags of a public key.
fn public_usage(allowed: &[Use]) -> Vec<Attribute> {
    vec![
        Attribute::Encrypt(on(allowed, Use::Encrypt)),
        Attribute::Verify(on(allowed, Use::Verify)),
        Attribute::VerifyRecover(on(allowed, Use::VerifyRecover)),
        Attribute::Wrap(on(allowed, Use::Wrap)),
    ]
}

fn failed(err: CkError) -> HsmError {
    HsmError::Failed(err.to_string())
}

/// Where the HSM is: the PKCS#11 module, the slot and the user PIN (a secret).
#[derive(Clone)]
pub struct Pkcs11Config {
    pub module: PathBuf,
    pub slot: u64,
    /// The user PIN, wiped from memory when the configuration is dropped.
    pub pin: Zeroizing<String>,
}

impl std::fmt::Debug for Pkcs11Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pkcs11Config")
            .field("module", &self.module)
            .field("slot", &self.slot)
            .field("pin", &"(hidden)")
            .finish()
    }
}

impl Pkcs11Config {
    /// Reads `ORBYN_HSM_MODULE`, `ORBYN_HSM_SLOT` and `ORBYN_HSM_PIN`. The errors name the
    /// setting and never echo the PIN.
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let need = |name: &str| {
            lookup(name)
                .filter(|v| !v.trim().is_empty())
                .ok_or_else(|| format!("{name} is not set"))
        };
        Ok(Self {
            module: PathBuf::from(need("ORBYN_HSM_MODULE")?),
            slot: need("ORBYN_HSM_SLOT")?
                .trim()
                .parse()
                .map_err(|_| "ORBYN_HSM_SLOT is not a slot number".to_owned())?,
            pin: Zeroizing::new(need("ORBYN_HSM_PIN")?),
        })
    }
}

/// A PKCS#11 HSM. Each operation opens its own session and logs in as the user; an unwrapped
/// account key lives in the session that made it until it is destroyed.
pub struct Pkcs11Hsm {
    context: Arc<Pkcs11>,
    slot: Slot,
    pin: AuthPin,
    sessions: Mutex<HashMap<u64, (Session, ObjectHandle)>>,
    next: Mutex<u64>,
}

/// SoftHSM is a PKCS#11 module; this is the same type.
pub type SoftHsm = Pkcs11Hsm;

impl Pkcs11Hsm {
    /// Loads the module and initialises it.
    pub fn open(config: &Pkcs11Config) -> Result<Self, HsmError> {
        let context = Pkcs11::new(&config.module).map_err(failed)?;
        match context.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
            Ok(()) | Err(CkError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
            Err(err) => return Err(failed(err)),
        }
        let slot = Slot::try_from(config.slot).map_err(|_| HsmError::Failed("bad slot".into()))?;
        Ok(Self::with_context(Arc::new(context), slot, &config.pin))
    }

    /// Uses a module that is already loaded and initialised, shared with other users of it.
    pub fn with_context(context: Arc<Pkcs11>, slot: Slot, pin: &str) -> Self {
        Self {
            context,
            slot,
            pin: AuthPin::from(pin.to_owned()),
            sessions: Mutex::new(HashMap::new()),
            next: Mutex::new(0),
        }
    }

    fn live(&self) -> MutexGuard<'_, HashMap<u64, (Session, ObjectHandle)>> {
        self.sessions.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// How many unwrapped keys are live as session objects.
    pub fn live_session_objects(&self) -> usize {
        self.live().len()
    }

    /// A logged-in session, for tests that look at what the HSM refuses (attribute reads of
    /// private keys, wrapping a non-extractable key). Only with `test-support`.
    #[cfg(feature = "test-support")]
    pub fn raw_session(&self) -> Result<Session, HsmError> {
        self.session()
    }

    /// Attributes of an unwrapped session key, as the HSM reports them. Only with `test-support`.
    #[cfg(feature = "test-support")]
    pub fn session_key_attribute_values(
        &self,
        key: &SessionKey,
        types: &[AttributeType],
    ) -> Result<Vec<Attribute>, HsmError> {
        let live = self.live();
        let (session, handle) = live.get(&key.0).ok_or(HsmError::NotFound)?;
        session.get_attributes(*handle, types).map_err(failed)
    }

    /// Whether an unwrapped session key is on the token, extractable and sensitive, as the HSM
    /// reports it. Only with `test-support`.
    #[cfg(feature = "test-support")]
    pub fn session_key_attributes(&self, key: &SessionKey) -> Result<(bool, bool, bool), HsmError> {
        let live = self.live();
        let (session, handle) = live.get(&key.0).ok_or(HsmError::NotFound)?;
        let attrs = session
            .get_attributes(
                *handle,
                &[
                    AttributeType::Token,
                    AttributeType::Extractable,
                    AttributeType::Sensitive,
                ],
            )
            .map_err(failed)?;
        let (mut token, mut extractable, mut sensitive) = (true, true, false);
        for attr in attrs {
            match attr {
                Attribute::Token(v) => token = v,
                Attribute::Extractable(v) => extractable = v,
                Attribute::Sensitive(v) => sensitive = v,
                _ => {}
            }
        }
        Ok((token, extractable, sensitive))
    }

    fn session(&self) -> Result<Session, HsmError> {
        let session = self.context.open_rw_session(self.slot).map_err(failed)?;
        match session.login(UserType::User, Some(&self.pin)) {
            Ok(()) | Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => Ok(session),
            Err(err) => Err(failed(err)),
        }
    }

    fn find(
        session: &Session,
        class: ObjectClass,
        label: &[u8],
    ) -> Result<Option<ObjectHandle>, HsmError> {
        let found = session
            .find_objects(&[Attribute::Class(class), Attribute::Label(label.to_vec())])
            .map_err(failed)?;
        Ok(found.into_iter().next())
    }

    fn kek(session: &Session) -> Result<ObjectHandle, HsmError> {
        Self::find(session, ObjectClass::SECRET_KEY, KEK_LABEL)?.ok_or(HsmError::NotFound)
    }

    /// Makes an Ed25519 signing key pair labelled `label`: non-extractable, for signing only.
    fn generate_signing_key(&self, label: Vec<u8>) -> Result<[u8; 32], HsmError> {
        let session = self.session()?;
        if Self::find(&session, ObjectClass::PRIVATE_KEY, &label)?.is_some() {
            return Err(HsmError::AlreadyExists);
        }
        let mut public_template = vec![
            Attribute::Token(true),
            Attribute::EcParams(ED25519_PARAMS.to_vec()),
            Attribute::Label(label.clone()),
        ];
        public_template.extend(public_usage(&[Use::Verify]));
        let mut private_template = vec![
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Label(label),
        ];
        private_template.extend(private_usage(&[Use::Sign]));
        let (public, _private) = session
            .generate_key_pair(
                &Mechanism::EccEdwardsKeyPairGen,
                &public_template,
                &private_template,
            )
            .map_err(failed)?;
        ed25519_public(&Self::point_of(&session, public)?)
    }

    /// The public key labelled `label`.
    fn signing_public(&self, label: &[u8]) -> Result<[u8; 32], HsmError> {
        let session = self.session()?;
        let public =
            Self::find(&session, ObjectClass::PUBLIC_KEY, label)?.ok_or(HsmError::NotFound)?;
        ed25519_public(&Self::point_of(&session, public)?)
    }

    fn point_of(session: &Session, public: ObjectHandle) -> Result<Vec<u8>, HsmError> {
        let attrs = session
            .get_attributes(public, &[AttributeType::EcPoint])
            .map_err(failed)?;
        match attrs.into_iter().next() {
            Some(Attribute::EcPoint(point)) => Ok(point),
            _ => Err(HsmError::BadKey),
        }
    }
}

impl crate::sealed::Sealed for Pkcs11Hsm {}

impl Hsm for Pkcs11Hsm {
    fn kek_exists(&self) -> Result<bool, HsmError> {
        let session = self.session()?;
        Ok(Self::find(&session, ObjectClass::SECRET_KEY, KEK_LABEL)?.is_some())
    }

    fn generate_kek(&self) -> Result<(), HsmError> {
        let session = self.session()?;
        if Self::find(&session, ObjectClass::SECRET_KEY, KEK_LABEL)?.is_some() {
            return Err(HsmError::AlreadyExists);
        }
        let mut template = vec![
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::ValueLen(32.into()),
            Attribute::Label(KEK_LABEL.to_vec()),
        ];
        template.extend(secret_usage(&[Use::Wrap, Use::Unwrap]));
        session
            .generate_key(&Mechanism::AesKeyGen, &template)
            .map_err(failed)?;
        Ok(())
    }

    fn identity_exists(&self, version: u32) -> Result<bool, HsmError> {
        let session = self.session()?;
        Ok(Self::find(&session, ObjectClass::PRIVATE_KEY, &identity_label(version))?.is_some())
    }

    fn generate_identity(&self, version: u32) -> Result<[u8; 32], HsmError> {
        self.generate_signing_key(identity_label(version))
    }

    fn identity_public(&self, version: u32) -> Result<[u8; 32], HsmError> {
        self.signing_public(&identity_label(version))
    }

    fn generate_log_key(&self, version: u32) -> Result<[u8; 32], HsmError> {
        self.generate_signing_key(log_key_label(version))
    }

    fn log_key_exists(&self, version: u32) -> Result<bool, HsmError> {
        let session = self.session()?;
        Ok(Self::find(&session, ObjectClass::PRIVATE_KEY, &log_key_label(version))?.is_some())
    }

    fn log_key_public(&self, version: u32) -> Result<[u8; 32], HsmError> {
        self.signing_public(&log_key_label(version))
    }

    fn sign(&self, version: u32, message: &HsmMessage) -> Result<[u8; 64], HsmError> {
        // The key set follows the message's kind.
        let label = match message.kind() {
            MessageKind::ServiceKeyStatement => identity_label(version),
            MessageKind::LogHead => log_key_label(version),
        };
        let session = self.session()?;
        let key =
            Self::find(&session, ObjectClass::PRIVATE_KEY, &label)?.ok_or(HsmError::NotFound)?;
        let signature = session
            .sign(
                &Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Pure)),
                key,
                message.signed_bytes(),
            )
            .map_err(failed)?;
        signature.try_into().map_err(|_| HsmError::BadKey)
    }

    fn generate_account_key(&self) -> Result<WrappedAccountKey, HsmError> {
        let session = self.session()?;
        let kek = Self::kek(&session)?;
        // Session objects, never on the token. The private half must be extractable for the
        // wrap, and sensitive, so it can leave only wrapped.
        let mut public_template = vec![
            Attribute::Token(false),
            Attribute::EcParams(P256_PARAMS.to_vec()),
        ];
        public_template.extend(public_usage(&[]));
        let mut private_template = vec![
            Attribute::Token(false),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(true),
        ];
        private_template.extend(private_usage(&[Use::Derive]));
        let (public, private) = session
            .generate_key_pair(
                &Mechanism::EccKeyPairGen,
                &public_template,
                &private_template,
            )
            .map_err(failed)?;
        let result = (|| {
            let wrapped = session
                .wrap_key(&Mechanism::AesKeyWrapPad, kek, private)
                .map_err(failed)?;
            let point = P256Point::from_hsm_point(&Self::point_of(&session, public)?)
                .map_err(|_| HsmError::BadKey)?;
            Ok(WrappedAccountKey {
                wrapped,
                public: point,
            })
        })();
        // The private key is gone from the HSM whatever happened.
        let _ = session.destroy_object(private);
        let _ = session.destroy_object(public);
        result
    }

    fn unwrap_account_key(&self, wrapped: &[u8]) -> Result<SessionKey, HsmError> {
        let session = self.session()?;
        let kek = Self::kek(&session)?;
        let mut template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::KeyType(KeyType::EC),
            Attribute::Token(false),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
        ];
        template.extend(private_usage(&[Use::Derive]));
        let handle = session
            .unwrap_key(&Mechanism::AesKeyWrapPad, kek, wrapped, &template)
            .map_err(failed)?;
        let mut next = self.next.lock().unwrap_or_else(PoisonError::into_inner);
        let id = *next;
        *next += 1;
        self.live().insert(id, (session, handle));
        Ok(SessionKey(id))
    }

    fn derive(
        &self,
        key: &SessionKey,
        ephemeral: &P256Point,
    ) -> Result<Zeroizing<[u8; 32]>, HsmError> {
        let live = self.live();
        let (session, handle) = live.get(&key.0).ok_or(HsmError::NotFound)?;
        let peer = ephemeral.uncompressed();
        let mut template = vec![
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::GENERIC_SECRET),
            Attribute::ValueLen(32.into()),
            Attribute::Token(false),
            Attribute::Sensitive(false),
            Attribute::Extractable(true),
        ];
        template.extend(secret_usage(&[]));
        let derived = session
            .derive_key(
                &Mechanism::Ecdh1Derive(Ecdh1DeriveParams::new(EcKdf::null(), &peer)),
                *handle,
                &template,
            )
            .map_err(failed)?;
        let value = session
            .get_attributes(derived, &[AttributeType::Value])
            .map_err(failed);
        let _ = session.destroy_object(derived);
        match value?.into_iter().next() {
            Some(Attribute::Value(bytes)) => {
                let bytes = Zeroizing::new(bytes);
                let mut out = Zeroizing::new([0u8; 32]);
                if bytes.len() != 32 {
                    return Err(HsmError::BadKey);
                }
                out.copy_from_slice(&bytes);
                Ok(out)
            }
            _ => Err(HsmError::BadKey),
        }
    }

    fn destroy(&self, key: SessionKey) -> Result<(), HsmError> {
        let (session, handle) = self.live().remove(&key.0).ok_or(HsmError::NotFound)?;
        let result = session.destroy_object(handle).map_err(failed);
        drop(session);
        result
    }
}

/// The 32-byte Ed25519 public key from `CKA_EC_POINT`, which wraps it in a DER OCTET STRING.
fn ed25519_public(point: &[u8]) -> Result<[u8; 32], HsmError> {
    let raw = match point {
        [0x04, 0x20, rest @ ..] if rest.len() == 32 => rest,
        other => other,
    };
    raw.try_into().map_err(|_| HsmError::BadKey)
}

/// What `orbyn keyservice init` does: makes the KEK and identity version 1 in the HSM the
/// environment names, and returns the identity's public key. Refuses if they exist.
pub fn init_from_env() -> Result<[u8; 32], String> {
    let config = Pkcs11Config::from_env()?;
    let hsm = Pkcs11Hsm::open(&config).map_err(|e| e.to_string())?;
    crate::KeyService::new(hsm)
        .init()
        .map_err(|e| e.to_string())
}
