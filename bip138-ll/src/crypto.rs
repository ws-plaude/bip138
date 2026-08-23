//! The crypto primitives the format needs, as traits the caller supplies. Keys
//! cross as raw 32-byte x-only public keys, so no elliptic-curve trait is
//! required. Bundled RustCrypto and OS-entropy implementations live behind the
//! `rust-crypto` and `os-rng` features for callers that do not bring their own.

use alloc::vec::Vec;

/// Deterministic primitives: SHA-256 and the ChaCha20-Poly1305 AEAD.
pub trait Crypto {
    /// One-shot SHA-256.
    fn sha256(&self, data: &[u8]) -> [u8; 32];

    /// ChaCha20-Poly1305 encrypt. The ciphertext is 16 bytes longer than the
    /// plaintext (the Poly1305 tag). `None` on any cipher failure.
    fn aead_encrypt(&self, key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Option<Vec<u8>>;

    /// ChaCha20-Poly1305 decrypt. `None` when the tag does not verify.
    fn aead_decrypt(&self, key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Option<Vec<u8>>;
}

/// A source of randomness for nonces and decoy secrets.
pub trait Rng {
    fn fill_bytes(&mut self, buf: &mut [u8]);
}

#[cfg(feature = "rust-crypto")]
mod rust_crypto {
    use super::Crypto;
    use alloc::vec::Vec;
    use chacha20poly1305::{
        ChaCha20Poly1305, Key, Nonce,
        aead::{Aead, KeyInit},
    };
    use sha2::{Digest, Sha256};

    /// Bundled SHA-256 and ChaCha20-Poly1305 from the RustCrypto crates.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct RustCrypto;

    impl Crypto for RustCrypto {
        fn sha256(&self, data: &[u8]) -> [u8; 32] {
            Sha256::digest(data).into()
        }

        fn aead_encrypt(
            &self,
            key: &[u8; 32],
            nonce: &[u8; 12],
            plaintext: &[u8],
        ) -> Option<Vec<u8>> {
            let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
            cipher.encrypt(Nonce::from_slice(nonce), plaintext).ok()
        }

        fn aead_decrypt(
            &self,
            key: &[u8; 32],
            nonce: &[u8; 12],
            ciphertext: &[u8],
        ) -> Option<Vec<u8>> {
            let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
            cipher.decrypt(Nonce::from_slice(nonce), ciphertext).ok()
        }
    }
}

#[cfg(feature = "rust-crypto")]
pub use rust_crypto::RustCrypto;

#[cfg(feature = "os-rng")]
mod os_rng {
    use super::Rng;
    use rand::{TryRngCore, rngs::OsRng};

    /// OS entropy source.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct OsRandom;

    impl Rng for OsRandom {
        fn fill_bytes(&mut self, buf: &mut [u8]) {
            OsRng.try_fill_bytes(buf).expect("os rng must not fail");
        }
    }
}

#[cfg(feature = "os-rng")]
pub use os_rng::OsRandom;
