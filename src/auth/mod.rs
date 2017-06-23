use base64;
use openssl::hash::MessageDigest;
use openssl::pkcs5;
use openssl::symm::{self, Cipher};
use ring::{digest, pbkdf2};
use ring::rand::{SecureRandom, SystemRandom};
use rmp_serde::{self, Deserializer, Serializer};
use serde::{Deserialize, Serialize};
use serialize::hex::{FromHex, ToHex};
use std::collections::HashMap;
use std::collections::hash_map::Keys;
use std::ffi::CString;

#[derive(Debug)]
pub enum AuthErr {
    KeyExists,
    KeyInvalid,
    KeyMissing,
    Serialize(rmp_serde::encode::Error),
}

impl From<rmp_serde::encode::Error> for AuthErr {
    fn from(e: rmp_serde::encode::Error) -> AuthErr {
        AuthErr::Serialize(e)
    }
}

pub type Result<T> = ::std::result::Result<T, AuthErr>;
const SALT_LEN: usize = 32;

fn create_random_salt(salt_len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; salt_len];

    let r = SystemRandom::new();
    r.fill(&mut buf);
    buf
}

// fn xxxxx(salt: &[u8], secret: &[u8]) {
//     const HASH_ITERATIONS: u32 = 4096;
// 
//     // need to hash the secret first
//     let mut hashed_secret = [0u8; digest::SHA1_OUTPUT_LEN];
// 
//     pbkdf2::derive(
//         &digest::SHA1,
//         HASH_ITERATIONS,
//         salt,
//         secret,
//         &mut hashed_secret);
// 
//     let hashed_secret_hex = hashed_secret.to_hex().to_lowercase();
// 
//     // aes-256 usually defaults to AES-256-CBC
//     // need to use the Poco algorithm to create the salt for AES decryption and key
//     const MD_ITERATIONS: i32 = 2000;
// 
//     let salt_bytes = {
//         let mut salt_bytes = [0u8; 8];
// 
//         if salt.len() > 0 {
//             let salt_len = salt.len();
// 
//             // Create the salt array from the salt string
//             for i in 0..8 {
//                 salt_bytes[i] = salt[i % salt_len];
//             }
// 
//             for i in 8..salt_len {
//                 salt_bytes[i % 8] ^= salt[i];
//             }
//         }
// 
//         salt_bytes
//     };
// 
//     let aes_salt = &salt_bytes[..];
//     let aes_algo = Cipher::aes_256_cbc();
// 
//     let key_iv = pkcs5::bytes_to_key(
//         aes_algo,
//         MessageDigest::md5(),
//         hashed_secret_hex.as_bytes(),
//         Some(aes_salt),
//         MD_ITERATIONS).unwrap();
//     
//     let iv_opt = match &key_iv.iv {
//         &Some(ref iv) => Some(iv.as_slice()),
//         &None => None,
//     };
// }

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

// impl AuthMgmt {
//     pub fn add<K, S, V>(&mut self, key: K, secret: S, value: &V) -> Result<()> where 
//         K: Into<String>,
//         S: Into<String>,
//         V: Serialize {
// 
//         let key = key.into();
//         
//         if !self.mapping.contains_key(&key) {
//             let mut buf = Vec::new();
//             value.serialize(&mut Serializer::new(&mut buf))?;
// 
//             let salt = create_random_salt(SALT_LEN);
//             unimplemented!();            
//             // self.mapping.insert(key, v)
//         } else {
//             Err(AuthErr::KeyExists)
//         }
//     }
// 
//     pub fn delete(&mut self, key: &str, secret: &str) -> Result<()> {
//         unimplemented!();
//     }
// 
//     pub fn force_delete(&mut self, key: &str) -> Result<()> {
//         self.mapping.remove(key)
//             .map(|_| ())
//             .ok_or_else(|| AuthErr::KeyMissing)
//     }
// 
//     pub fn update<V: Serialize>(&mut self, key: &str, secret: &str, value: &V) -> Result<()> {
//         unimplemented!();
//     }
// 
//     pub fn force_update<V: Serialize>(&mut self, key: &str, value: &V) -> Result<()> {
//         unimplemented!();
//     }
// 
//     pub fn exchange<'a, D: Deserialize<'a>>(&self, key: &str, secret: &str) -> Result<D> where {
//         unimplemented!();
//     }
// 
//     pub fn get_keys(&self) -> Keys<String, SaltEncryptedPayloadGroup> {
//         self.mapping.keys()
//     }
// }
