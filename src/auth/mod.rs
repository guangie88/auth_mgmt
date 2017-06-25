use base64;
use openssl;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkcs5::{self, KeyIvPair};
use openssl::symm::{self, Cipher};
use ring::{digest, pbkdf2};
use ring::rand::{SecureRandom, SystemRandom};
use rmp_serde::{self, Deserializer, Serializer};
use serde::{Deserialize, Serialize};
use serialize::hex::{FromHex, ToHex};
use std;
use std::collections::HashMap;
use std::collections::hash_map::Keys;
use std::ffi::{CString, NulError};

#[derive(Debug)]
pub enum AuthErr {
    Ffi(NulError),
    KeyExists,
    KeyInvalid,
    KeyMissing,
    Pkcs5(ErrorStack),
    Serialize(rmp_serde::encode::Error),
}

impl From<NulError> for AuthErr {
    fn from(e: NulError) -> AuthErr {
        AuthErr::Ffi(e)
    }
}

impl From<rmp_serde::encode::Error> for AuthErr {
    fn from(e: rmp_serde::encode::Error) -> AuthErr {
        AuthErr::Serialize(e)
    }
}

impl From<ErrorStack> for AuthErr {
    fn from(e: ErrorStack) -> AuthErr {
        AuthErr::Pkcs5(e)
    }
}

pub type Result<T> = std::result::Result<T, AuthErr>;
const SALT_LEN: usize = 32;
const HASH_ITERATIONS: u32 = 4096;

fn create_random_salt(salt_len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; salt_len];

    let r = SystemRandom::new();
    r.fill(&mut buf);
    buf
}

fn get_aes_algo() -> Cipher {
    Cipher::aes_256_cbc()
}

fn derive_key_iv_pair(salt: &[u8], secret: &[u8]) -> Result<KeyIvPair> {
    // need to hash the secret first
    let mut hashed_secret = [0u8; digest::SHA1_OUTPUT_LEN];

    pbkdf2::derive(
        &digest::SHA1,
        HASH_ITERATIONS,
        salt,
        secret,
        &mut hashed_secret);

    let hashed_secret_hex = hashed_secret.to_hex().to_lowercase();

    // aes-256 usually defaults to AES-256-CBC
    // need to use the Poco algorithm to create the salt for AES decryption and key
    const MD_ITERATIONS: i32 = 2000;

    let salt_bytes = {
        let mut salt_bytes = [0u8; 8];

        if salt.len() > 0 {
            let salt_len = salt.len();

            // Create the salt array from the salt string
            for i in 0..8 {
                salt_bytes[i] = salt[i % salt_len];
            }

            for i in 8..salt_len {
                salt_bytes[i % 8] ^= salt[i];
            }
        }

        salt_bytes
    };

    let aes_salt = &salt_bytes[..];

    let key_iv = pkcs5::bytes_to_key(
        get_aes_algo(),
        MessageDigest::md5(),
        hashed_secret_hex.as_bytes(),
        Some(aes_salt),
        MD_ITERATIONS)?;

    Ok(key_iv)
}

#[derive(new, Debug, PartialEq, Deserialize, Serialize)]
pub struct SaltEncryptedPayloadGroup {
    pub salt: CString,
    pub encrypted_hashhex_payload_b64: CString,
}

#[derive(new, Debug, PartialEq, Deserialize, Serialize)]
pub struct AuthMgmt {
    pub mapping: HashMap<String, SaltEncryptedPayloadGroup>,
    pub cipher_algo_name: String,
}

impl AuthMgmt {
    pub fn add<K, S, V>(&mut self, key: K, secret: S, value: &V) -> Result<()> where 
        K: Into<String>,
        S: Into<String>,
        V: Serialize {

        let key = key.into();
        
        if !self.mapping.contains_key(&key) {
            let mut payload = Vec::new();
            value.serialize(&mut Serializer::new(&mut payload))?;
            let payload = payload;

            let salt = create_random_salt(SALT_LEN);
            let key_iv = derive_key_iv_pair(salt.as_slice(), secret.into().as_bytes())?;

            // binary hash of payload
            let mut payload_hash = [0u8; digest::SHA1_OUTPUT_LEN];

            pbkdf2::derive(
                &digest::SHA1,
                HASH_ITERATIONS,
                salt.as_slice(),
                payload.as_slice(),
                &mut payload_hash);
            
            // need to convery to hex representation
            let payload_hashhex = payload_hash.to_hex().to_lowercase()
                .into_bytes();
            
            let hashhex_payload: Vec<u8> = payload_hashhex.into_iter()
                .chain(payload)
                .collect();

            let iv_opt = match &key_iv.iv {
                &Some(ref iv) => Some(iv.as_slice()),
                &None => None,
            };

            let encrypted_hashhex_payload = symm::encrypt(
                get_aes_algo(),
                &key_iv.key,
                iv_opt,
                hashhex_payload.as_slice())?;

            let encrypted_hashhex_payload_b64 = {
                let mut buf = String::new();
                base64::encode_config_buf(encrypted_hashhex_payload.as_slice(), base64::MIME, &mut buf);
                buf.into_bytes()
            };

            let salt_with_encrypted_hashhex_payload_b64 = SaltEncryptedPayloadGroup::new(
                CString::new(salt)?,
                CString::new(encrypted_hashhex_payload_b64)?);

            // ignore the possible Option
            // because the value has been checked before insertion
            let _ = self.mapping.insert(key, salt_with_encrypted_hashhex_payload_b64);
            
            Ok(())
        } else {
            Err(AuthErr::KeyExists)
        }
    }

    pub fn delete(&mut self, key: &str, secret: &str) -> Result<()> {
        unimplemented!();
    }

    pub fn force_delete(&mut self, key: &str) -> Result<()> {
        self.mapping.remove(key)
            .map(|_| ())
            .ok_or_else(|| AuthErr::KeyMissing)
    }

    pub fn update<V: Serialize>(&mut self, key: &str, secret: &str, value: &V) -> Result<()> {
        unimplemented!();
    }

    pub fn force_update<V: Serialize>(&mut self, key: &str, value: &V) -> Result<()> {
        unimplemented!();
    }

    pub fn exchange<'a, D: Deserialize<'a>>(&self, key: &str, secret: &str) -> Result<D> where {
        unimplemented!();
    }

    pub fn get_keys(&self) -> Keys<String, SaltEncryptedPayloadGroup> {
        self.mapping.keys()
    }
}
