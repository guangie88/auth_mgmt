use base64::{self, DecodeError};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkcs5::{self, KeyIvPair};
use openssl::symm::{self, Cipher};
use ring::{digest, pbkdf2};
use ring::error::Unspecified;
use ring::rand::{SecureRandom, SystemRandom};
use rmp_serde::{self, Deserializer, Serializer};
use serde::{Deserialize, Serialize};
use serialize::hex::{FromHex, FromHexError, ToHex};
use std;
use std::str::{self, Utf8Error};
use std::collections::HashMap;
use std::collections::hash_map::Keys;
use std::ffi::{CString, NulError};

#[derive(Debug)]
pub enum AuthErr {
    Base64(DecodeError),
    Ffi(NulError),
    HexSerialize(FromHexError),
    KeyExists,
    KeyInvalid,
    KeyMissing,
    Pkcs5(ErrorStack),
    Ring(Unspecified),
    RmpSerdeDecode(rmp_serde::decode::Error),
    RmpSerdeEncode(rmp_serde::encode::Error),
    Str(Utf8Error),
}

impl From<DecodeError> for AuthErr {
    fn from(e: DecodeError) -> AuthErr {
        AuthErr::Base64(e)
    }
}

impl From<NulError> for AuthErr {
    fn from(e: NulError) -> AuthErr {
        AuthErr::Ffi(e)
    }
}

impl From<FromHexError> for AuthErr {
    fn from(e: FromHexError) -> AuthErr {
        AuthErr::HexSerialize(e)
    }
}

impl From<ErrorStack> for AuthErr {
    fn from(e: ErrorStack) -> AuthErr {
        AuthErr::Pkcs5(e)
    }
}

impl From<Unspecified> for AuthErr {
    fn from(e: Unspecified) -> AuthErr {
        AuthErr::Ring(e)
    }
}

impl From<rmp_serde::decode::Error> for AuthErr {
    fn from(e: rmp_serde::decode::Error) -> AuthErr {
        AuthErr::RmpSerdeDecode(e)
    }
}

impl From<rmp_serde::encode::Error> for AuthErr {
    fn from(e: rmp_serde::encode::Error) -> AuthErr {
        AuthErr::RmpSerdeEncode(e)
    }
}

impl From<Utf8Error> for AuthErr {
    fn from(e: Utf8Error) -> AuthErr {
        AuthErr::Str(e)
    }
}

pub type Result<T> = std::result::Result<T, AuthErr>;

const SALT_LEN: usize = 32;
const HASH_ITERATIONS: u32 = 4096;
const MD_ITERATIONS: i32 = 2000;
const CIPHER_ALGO_NAME: &'static str = "aes256";

// multiply by 2 because hex has twice the length from binary u8 representation
const SHA1_DIGEST_HEX_COUNT: usize = digest::SHA1_OUTPUT_LEN * 2;

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

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct AuthMgmt {
    pub mapping: HashMap<String, SaltEncryptedPayloadGroup>,
    pub cipher_algo_name: String,
}

impl AuthMgmt {
    pub fn new() -> AuthMgmt {
        AuthMgmt {
            mapping: HashMap::new(),
            cipher_algo_name: CIPHER_ALGO_NAME.to_owned(),
        }
    }

    pub fn from_mapping<M>(mapping: M) -> AuthMgmt where
        M: Into<HashMap<String, SaltEncryptedPayloadGroup>> {

        AuthMgmt {
            mapping: HashMap::new(),
            cipher_algo_name: CIPHER_ALGO_NAME.to_owned(),
        }
    }

    pub fn add<K, S, V>(&mut self, key: K, secret: S, value: &V) -> Result<()> where 
        K: Into<String>,
        S: Into<String>,
        V: Serialize {

        let key = key.into();

        if self.mapping.contains_key(&key) {
            Err(AuthErr::KeyExists)?;
        }

        let secret = secret.into();
        let salt_with_encrypted_hashhex_payload_b64 = self.prep_salt_with_encrypted_hashhex_payload_b64(&key, &secret, value)?;

        // ignore the possible Option
        // because the value has been checked before insertion
        let _ = self.mapping.insert(key, salt_with_encrypted_hashhex_payload_b64);
        Ok(())
    }

    pub fn add_raw<K, S, P>(&mut self, key: K, secret: S, payload: P) -> Result<()> where
        K: Into<String>,
        S: Into<String>,
        P: Into<Vec<u8>> {

        let key = key.into();

        if self.mapping.contains_key(&key) {
            Err(AuthErr::KeyExists)?;
        }

        let secret = secret.into();
        let payload = payload.into();
        let salt_with_encrypted_hashhex_payload_raw_b64 = self.prep_salt_with_encrypted_hashhex_payload_raw_b64(&key, &secret, payload)?;

        // ignore the possible Option
        // because the value has been checked before insertion
        let _ = self.mapping.insert(key, salt_with_encrypted_hashhex_payload_raw_b64);
        Ok(())
    }

    pub fn delete(&mut self, key: &str, secret: &str) -> Result<()> {
        self.verify(key, secret)?;
        self.force_delete(key)
    }

    pub fn force_delete(&mut self, key: &str) -> Result<()> {
        self.mapping.remove(key)
            .map(|_| ())
            .ok_or_else(|| AuthErr::KeyMissing)
    }

    pub fn update<V: Serialize>(&mut self, key: &str, secret: &str, value: &V) -> Result<()> {
        self.verify(key, secret)?;
        let salt_with_encrypted_hashhex_payload_b64 = self.prep_salt_with_encrypted_hashhex_payload_b64(&key, &secret, value)?;

        let mapping_value = self.mapping.get_mut(key).ok_or_else(|| AuthErr::KeyMissing)?;
        *mapping_value = salt_with_encrypted_hashhex_payload_b64;
        Ok(())
    }

    pub fn exchange<'a, D: Deserialize<'a>>(&self, key: &str, secret: &str) -> Result<D> where {
        let payload = self.verify(key, secret)?;

        let mut de = Deserializer::new(payload.as_slice());
        let value: D = Deserialize::deserialize(&mut de)?;
        Ok(value)
    }

    // this is equivalent to exchange_raw (like add to add_raw)
    pub fn verify(&self, key: &str, secret: &str) -> Result<Vec<u8>> {
        let salt_with_encrypted_hashhex_payload_b64 = self.mapping.get(key)
            .ok_or_else(|| AuthErr::KeyMissing)?;

        let salt = salt_with_encrypted_hashhex_payload_b64.salt.as_bytes();
        let encrypted_hashhex_payload_b64 = salt_with_encrypted_hashhex_payload_b64.encrypted_hashhex_payload_b64.as_bytes();
        let key_iv = derive_key_iv_pair(salt, secret.as_bytes())?;
        
        // payload is in base64, so convert it back into binary first before decryption
        let encrypted_hashhex_payload = {
            let mut buf = Vec::new();
            base64::decode_config_buf(encrypted_hashhex_payload_b64, base64::MIME, &mut buf)?;
            buf
        };

        let iv_opt = match &key_iv.iv {
            &Some(ref iv) => Some(iv.as_slice()),
            &None => None,
        };

        let hashhex_payload = symm::decrypt(
            get_aes_algo(),
            &key_iv.key,
            iv_opt,
            encrypted_hashhex_payload.as_slice())?;

        // need to convert hex back into binary for the originally attached hash value derived from the payload
        let payload_hashhex = &hashhex_payload[0..SHA1_DIGEST_HEX_COUNT];
        let payload_hash = str::from_utf8(payload_hashhex)?.from_hex()?;
        let payload = &hashhex_payload[SHA1_DIGEST_HEX_COUNT..];

        pbkdf2::verify(
            &digest::SHA1,
            HASH_ITERATIONS,
            salt,
            payload,
            payload_hash.as_slice())?;
        
        Ok(payload.to_vec())
    }

    pub fn get_keys(&self) -> Keys<String, SaltEncryptedPayloadGroup> {
        self.mapping.keys()
    }

    fn prep_salt_with_encrypted_hashhex_payload_b64<V>(&self, key: &str, secret: &str, value: &V) -> Result<SaltEncryptedPayloadGroup> where
        V: Serialize {
        
        let mut payload = Vec::new();
        value.serialize(&mut Serializer::new(&mut payload))?;
        let payload = payload;

        self.prep_salt_with_encrypted_hashhex_payload_raw_b64(key, secret, payload)
    }

    fn prep_salt_with_encrypted_hashhex_payload_raw_b64<P>(&self, key: &str, secret: &str, payload: P) -> Result<SaltEncryptedPayloadGroup> where
        P: Into<Vec<u8>> {

        let payload = payload.into();
        let salt = create_random_salt(SALT_LEN);
        let key_iv = derive_key_iv_pair(salt.as_slice(), secret.as_bytes())?;

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

        Ok(salt_with_encrypted_hashhex_payload_b64)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use file;
    use std::fs;

    // payload == b"Hello how are you today?"
    const HELLO_WORLD_KNOWN_SALT_BUF: [u8; 130] = [
        0x92, 0x81, 0xA5, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x92, 0xA1,
        0x88, 0xD9, 0x6E, 0x61, 0x6D, 0x35, 0x66, 0x59, 0x62, 0x38,
        0x54, 0x44, 0x54, 0x52, 0x4B, 0x36, 0x62, 0x4D, 0x6B, 0x77,
        0x78, 0x4F, 0x79, 0x57, 0x71, 0x75, 0x2F, 0x77, 0x78, 0x4E,
        0x48, 0x62, 0x5A, 0x6D, 0x50, 0x61, 0x66, 0x2F, 0x39, 0x48,
        0x79, 0x57, 0x69, 0x55, 0x46, 0x74, 0x4A, 0x4B, 0x4F, 0x61,
        0x51, 0x63, 0x52, 0x47, 0x6B, 0x41, 0x33, 0x41, 0x67, 0x75,
        0x67, 0x69, 0x52, 0x51, 0x38, 0x50, 0x51, 0x31, 0x51, 0x68,
        0x30, 0x51, 0x6F, 0x7A, 0x72, 0x0D, 0x0A, 0x57, 0x75, 0x32,
        0x68, 0x37, 0x69, 0x6D, 0x5A, 0x53, 0x67, 0x52, 0x67, 0x63,
        0x56, 0x6E, 0x68, 0x54, 0x59, 0x46, 0x62, 0x45, 0x2F, 0x79,
        0x6D, 0x4D, 0x72, 0x69, 0x71, 0x33, 0x39, 0x37, 0x2F, 0x2F,
        0x6B, 0x67, 0x3D, 0xA6, 0x61, 0x65, 0x73, 0x32, 0x35, 0x36];

    #[test]
    fn test_auth_mgmt_serializable() {
        const WRITE_PATH: &'static str = "test_new_exchanger.bin";

        let mut buf = Vec::new();

        let hm = {
            let mut hm = HashMap::new();

            hm.insert(
                "hello".to_owned(),
                SaltEncryptedPayloadGroup::new(
                    CString::new("^").unwrap(),
                    CString::new("howareyou").unwrap()));

            hm
        };

        let auth_mgmt = AuthMgmt::from_mapping(hm);
        auth_mgmt.serialize(&mut Serializer::new(&mut buf)).unwrap();
        file::put(WRITE_PATH, &buf[..]).unwrap();

        let do_remove_file = fs::remove_file(WRITE_PATH);
        assert!(do_remove_file.is_ok());
    }

    #[test]
    fn test_exchange_hello_world_known_salt() {
        let buf = &HELLO_WORLD_KNOWN_SALT_BUF[..];
        let mut de = Deserializer::new(buf);

        let auth_mgmt: AuthMgmt = Deserialize::deserialize(&mut de)
            .expect("Unable to deserialize buffer content into AuthMgmt");

        let payload = auth_mgmt.verify("hello", "world").unwrap();

        assert!(payload.into_iter()
            .zip(b"Hello how are you today?".iter())
            .all(|(l, r)| l == *r));
    }

    #[test]
    fn test_add_exchange_hello_world() {
        let orig_payload = "This is a custom payload!".to_owned();

        // add
        let mut auth_mgmt = AuthMgmt::new();
        auth_mgmt.add("hello", "world", &orig_payload);

        // exchange
        let value: String = auth_mgmt.exchange("hello", "world").unwrap();
        assert!(value == orig_payload);
    }
}