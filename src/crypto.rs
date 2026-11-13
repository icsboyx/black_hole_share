//! Encryption of shared files and of their keys.
//!
//! A file is encrypted with its own random 256-bit key (AES-256-GCM), in chunks of
//! [`PLAIN_CHUNK_BYTES`], so it can be streamed in both directions without holding it in
//! memory. The nonce of each chunk is its index plus a "last chunk" flag: chunks cannot be
//! reordered, dropped or appended without the decryption failing. A counter nonce is safe
//! because every key encrypts exactly one file.
//!
//! The file key is given to the admin to send to the downloader, and is also stored wrapped
//! for the admin's X25519 public key, so the admin can show it again. The admin's private
//! key is stored encrypted with a key derived from the admin password (Argon2id): without
//! the password, nothing on disk reveals a file key.

use aes_gcm::{
    Aes256Gcm,
    aead::{AeadInOut, KeyInit},
};
use anyhow::{Context, Result, anyhow};
use argon2::Argon2;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

pub const KEY_BYTES: usize = 32;
pub const PLAIN_CHUNK_BYTES: usize = 64 * 1024;
pub const TAG_BYTES: usize = 16;
const NONCE_BYTES: usize = 12;
const SALT_BYTES: usize = 16;

/// Bound into every file chunk, so a chunk can only be read as a chunk of this format.
const FILE_AAD: &[u8] = b"bhs-file-v1";
const PRIVATE_KEY_AAD: &[u8] = b"bhs-admin-private-key-v1";
const WRAP_INFO: &[u8] = b"bhs-file-key-wrap-v1";

fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|e| anyhow!("no secure random source: {e}"))?;
    Ok(bytes)
}

fn decode_fixed<const N: usize>(text: &str) -> Option<[u8; N]> {
    URL_SAFE_NO_PAD.decode(text).ok()?.try_into().ok()
}

/// The key of one encrypted file. Its memory is wiped when it is dropped.
pub struct FileKey([u8; KEY_BYTES]);

impl FileKey {
    pub fn generate() -> Result<Self> {
        Ok(Self(random_bytes()?))
    }

    /// The text form given to the downloader: 43 URL-safe base64 characters.
    pub fn encode(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    /// Parses the text form. Surrounding spaces from copy and paste are ignored.
    pub fn decode(text: &str) -> Option<Self> {
        decode_fixed(text.trim()).map(Self)
    }
}

impl Drop for FileKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Number of chunks of an encrypted file. An empty file still has one (empty) chunk, so its
/// "last chunk" flag is authenticated too.
pub fn chunk_count(plain_size: u64) -> u64 {
    plain_size.div_ceil(PLAIN_CHUNK_BYTES as u64).max(1)
}

/// Size on disk of an encrypted file.
pub fn encrypted_size(plain_size: u64) -> u64 {
    plain_size + chunk_count(plain_size) * TAG_BYTES as u64
}

/// Plaintext length of chunk `index` of a file of `plain_size` bytes.
pub fn plain_chunk_len(plain_size: u64, index: u64) -> usize {
    let start = index * PLAIN_CHUNK_BYTES as u64;
    plain_size
        .saturating_sub(start)
        .min(PLAIN_CHUNK_BYTES as u64) as usize
}

#[derive(Debug, PartialEq, Eq)]
pub struct DecryptError;

/// Encrypts and decrypts the chunks of one file.
pub struct ChunkCipher(Aes256Gcm);

impl ChunkCipher {
    pub fn new(key: &FileKey) -> Self {
        Self(Aes256Gcm::new(&key.0.into()))
    }

    fn nonce(index: u64, last: bool) -> [u8; NONCE_BYTES] {
        let mut nonce = [0u8; NONCE_BYTES];
        nonce[..8].copy_from_slice(&index.to_be_bytes());
        nonce[NONCE_BYTES - 1] = u8::from(last);
        nonce
    }

    /// Replaces the plaintext in `buffer` with the ciphertext and its tag.
    pub fn seal(&self, index: u64, last: bool, buffer: &mut Vec<u8>) -> Result<()> {
        self.0
            .encrypt_in_place(&Self::nonce(index, last).into(), FILE_AAD, buffer)
            .map_err(|_| anyhow!("chunk encryption failed"))
    }

    /// Replaces the ciphertext and tag in `buffer` with the plaintext. Fails for a wrong
    /// key or a chunk that was changed, moved or cut.
    pub fn open(&self, index: u64, last: bool, buffer: &mut Vec<u8>) -> Result<(), DecryptError> {
        self.0
            .decrypt_in_place(&Self::nonce(index, last).into(), FILE_AAD, buffer)
            .map_err(|_| DecryptError)
    }
}

/// A file key encrypted for the admin's public key (ECIES: X25519 + HKDF-SHA256 + AES-GCM).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedKey {
    ephemeral_public: String,
    nonce: String,
    ciphertext: String,
}

fn wrapping_cipher(shared: &[u8; 32], ephemeral: &PublicKey, admin: &PublicKey) -> Aes256Gcm {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(ephemeral.as_bytes());
    salt[32..].copy_from_slice(admin.as_bytes());
    let mut key = Zeroizing::new([0u8; KEY_BYTES]);
    Hkdf::<Sha256>::new(Some(&salt), shared)
        .expand(WRAP_INFO, key.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    Aes256Gcm::new(&(*key).into())
}

pub fn wrap_file_key(admin: &PublicKey, key: &FileKey) -> Result<WrappedKey> {
    let ephemeral_secret = StaticSecret::from(random_bytes::<32>()?);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    let shared = ephemeral_secret.diffie_hellman(admin);
    let cipher = wrapping_cipher(shared.as_bytes(), &ephemeral_public, admin);
    let nonce: [u8; NONCE_BYTES] = random_bytes()?;
    let mut buffer = key.0.to_vec();
    cipher
        .encrypt_in_place(&nonce.into(), &[], &mut buffer)
        .map_err(|_| anyhow!("file key wrapping failed"))?;
    Ok(WrappedKey {
        ephemeral_public: URL_SAFE_NO_PAD.encode(ephemeral_public.as_bytes()),
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(&buffer),
    })
}

pub fn unwrap_file_key(admin: &StaticSecret, wrapped: &WrappedKey) -> Result<FileKey> {
    let ephemeral_public = PublicKey::from(
        decode_fixed::<32>(&wrapped.ephemeral_public).context("invalid wrapped key")?,
    );
    let nonce = decode_fixed::<NONCE_BYTES>(&wrapped.nonce).context("invalid wrapped key")?;
    let mut buffer = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(&wrapped.ciphertext)
            .context("invalid wrapped key")?,
    );
    let shared = admin.diffie_hellman(&ephemeral_public);
    let cipher = wrapping_cipher(
        shared.as_bytes(),
        &ephemeral_public,
        &PublicKey::from(admin),
    );
    cipher
        .decrypt_in_place(&nonce.into(), &[], &mut *buffer)
        .map_err(|_| anyhow!("the file key cannot be unwrapped with this admin key"))?;
    let key: [u8; KEY_BYTES] = buffer
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("wrapped file key has the wrong length"))?;
    Ok(FileKey(key))
}

/// The admin's key pair as stored on disk: the public key in clear, the private key
/// encrypted with a key derived from the admin password.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminKeyPair {
    public_key: String,
    salt: String,
    nonce: String,
    encrypted_private_key: String,
}

#[derive(Debug)]
pub enum OpenKeyError {
    WrongPassword,
    Internal(anyhow::Error),
}

fn password_cipher(password: &str, salt: &[u8]) -> Result<Aes256Gcm> {
    let mut key = Zeroizing::new([0u8; KEY_BYTES]);
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|e| anyhow!("key derivation failed: {e}"))?;
    Ok(Aes256Gcm::new(&(*key).into()))
}

impl AdminKeyPair {
    /// Creates a new key pair protected by `password`. Runs Argon2: call it off the async
    /// worker threads.
    pub fn generate(password: &str) -> Result<Self> {
        Self::seal(&StaticSecret::from(random_bytes::<32>()?), password)
    }

    /// Stores `secret` protected by `password`, with a fresh salt and nonce. Runs Argon2.
    pub fn seal(secret: &StaticSecret, password: &str) -> Result<Self> {
        let salt: [u8; SALT_BYTES] = random_bytes()?;
        let nonce: [u8; NONCE_BYTES] = random_bytes()?;
        let mut buffer = secret.to_bytes().to_vec();
        password_cipher(password, &salt)?
            .encrypt_in_place(&nonce.into(), PRIVATE_KEY_AAD, &mut buffer)
            .map_err(|_| anyhow!("private key encryption failed"))?;
        Ok(Self {
            public_key: URL_SAFE_NO_PAD.encode(PublicKey::from(secret).as_bytes()),
            salt: URL_SAFE_NO_PAD.encode(salt),
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            encrypted_private_key: URL_SAFE_NO_PAD.encode(&buffer),
        })
    }

    pub fn public_key(&self) -> Result<PublicKey> {
        decode_fixed::<32>(&self.public_key)
            .map(PublicKey::from)
            .context("invalid admin public key")
    }

    /// Decrypts the private key. Runs Argon2: call it off the async worker threads.
    pub fn open(&self, password: &str) -> Result<StaticSecret, OpenKeyError> {
        let internal = OpenKeyError::Internal;
        let salt = URL_SAFE_NO_PAD
            .decode(&self.salt)
            .context("invalid admin key salt")
            .map_err(internal)?;
        let nonce = decode_fixed::<NONCE_BYTES>(&self.nonce)
            .context("invalid admin key nonce")
            .map_err(internal)?;
        let mut buffer = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(&self.encrypted_private_key)
                .context("invalid encrypted admin key")
                .map_err(internal)?,
        );
        password_cipher(password, &salt)
            .map_err(internal)?
            .decrypt_in_place(&nonce.into(), PRIVATE_KEY_AAD, &mut *buffer)
            .map_err(|_| OpenKeyError::WrongPassword)?;
        let bytes: [u8; 32] = buffer
            .as_slice()
            .try_into()
            .map_err(|_| internal(anyhow!("admin private key has the wrong length")))?;
        let secret = StaticSecret::from(bytes);
        let public = self.public_key().map_err(internal)?;
        if PublicKey::from(&secret) != public {
            return Err(internal(anyhow!(
                "admin private key does not match its public key"
            )));
        }
        Ok(secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encrypt_all(key: &FileKey, plain: &[u8]) -> Vec<Vec<u8>> {
        let cipher = ChunkCipher::new(key);
        let count = chunk_count(plain.len() as u64);
        (0..count)
            .map(|index| {
                let len = plain_chunk_len(plain.len() as u64, index);
                let start = index as usize * PLAIN_CHUNK_BYTES;
                let mut chunk = plain[start..start + len].to_vec();
                cipher.seal(index, index + 1 == count, &mut chunk).unwrap();
                chunk
            })
            .collect()
    }

    fn decrypt_all(key: &FileKey, chunks: &[Vec<u8>]) -> Result<Vec<u8>, DecryptError> {
        let cipher = ChunkCipher::new(key);
        let mut plain = Vec::new();
        for (index, chunk) in chunks.iter().enumerate() {
            let mut chunk = chunk.clone();
            cipher.open(index as u64, index + 1 == chunks.len(), &mut chunk)?;
            plain.extend_from_slice(&chunk);
        }
        Ok(plain)
    }

    #[test]
    fn chunks_round_trip_for_every_size_boundary() {
        let key = FileKey::generate().unwrap();
        for size in [
            0,
            1,
            PLAIN_CHUNK_BYTES - 1,
            PLAIN_CHUNK_BYTES,
            PLAIN_CHUNK_BYTES + 1,
            3 * PLAIN_CHUNK_BYTES + 7,
        ] {
            let plain: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let chunks = encrypt_all(&key, &plain);
            let on_disk: usize = chunks.iter().map(Vec::len).sum();
            assert_eq!(on_disk as u64, encrypted_size(size as u64), "size {size}");
            assert_eq!(decrypt_all(&key, &chunks).unwrap(), plain, "size {size}");
        }
    }

    #[test]
    fn wrong_key_and_tampering_are_detected() {
        let key = FileKey::generate().unwrap();
        let plain = vec![7u8; 2 * PLAIN_CHUNK_BYTES + 10];
        let chunks = encrypt_all(&key, &plain);

        let other = FileKey::generate().unwrap();
        assert_eq!(decrypt_all(&other, &chunks), Err(DecryptError));

        let mut flipped = chunks.clone();
        flipped[1][5] ^= 1;
        assert_eq!(decrypt_all(&key, &flipped), Err(DecryptError));

        let mut swapped = chunks.clone();
        swapped.swap(0, 1);
        assert_eq!(decrypt_all(&key, &swapped), Err(DecryptError));

        // Dropping the last chunk makes the new last one fail its "last" flag.
        assert_eq!(decrypt_all(&key, &chunks[..2]), Err(DecryptError));
    }

    #[test]
    fn file_key_text_form_round_trips_and_rejects_garbage() {
        let key = FileKey::generate().unwrap();
        let text = key.encode();
        assert_eq!(text.len(), 43);
        assert_eq!(FileKey::decode(&format!(" {text}\n")).unwrap().0, key.0);
        assert!(FileKey::decode("short").is_none());
        assert!(FileKey::decode(&format!("{text}AA")).is_none());
        assert!(FileKey::decode("!!!").is_none());
    }

    #[test]
    fn file_key_is_unwrapped_only_with_the_admin_password() {
        let pair = AdminKeyPair::generate("correct horse").unwrap();
        let key = FileKey::generate().unwrap();
        let wrapped = wrap_file_key(&pair.public_key().unwrap(), &key).unwrap();

        assert!(matches!(
            pair.open("wrong horse"),
            Err(OpenKeyError::WrongPassword)
        ));
        let secret = pair.open("correct horse").unwrap();
        assert_eq!(unwrap_file_key(&secret, &wrapped).unwrap().0, key.0);

        // A new password keeps the same key pair, so old wrapped keys still open.
        let resealed = AdminKeyPair::seal(&secret, "new password").unwrap();
        assert!(matches!(
            resealed.open("correct horse"),
            Err(OpenKeyError::WrongPassword)
        ));
        let secret = resealed.open("new password").unwrap();
        assert_eq!(unwrap_file_key(&secret, &wrapped).unwrap().0, key.0);

        let stranger = AdminKeyPair::generate("someone else").unwrap();
        let stranger = stranger.open("someone else").unwrap();
        assert!(unwrap_file_key(&stranger, &wrapped).is_err());
    }
}
