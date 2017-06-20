#![feature(rustc_private)]

extern crate base64;

#[macro_use]
extern crate derive_new;

#[macro_use]
extern crate error_chain;
extern crate file;
extern crate filebuffer;

#[macro_use]
extern crate log;
extern crate log4rs;
extern crate openssl;
extern crate ring;
extern crate rmp;
extern crate rmp_serde;
extern crate serde;

#[macro_use]
extern crate serde_derive;
extern crate serialize;
extern crate simple_logger;
extern crate structopt;

#[macro_use]
extern crate structopt_derive;

use filebuffer::FileBuffer;
use openssl::hash::MessageDigest;
use openssl::pkcs5;
use openssl::symm::{self, Cipher};
use ring::{digest, pbkdf2};
use rmp_serde::{Deserializer, Serializer};
use serde::{Deserialize, Serialize};
use serialize::hex::{FromHex, ToHex};
use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::process;
use std::str;
use structopt::StructOpt;

mod errors {
    error_chain! {
        errors {
        }
    }
}

use errors::*;

#[derive(StructOpt, Debug)]
#[structopt(name = "Authentication Management", about = "Program to perform authentication management.")]
struct MainConfig {
    #[structopt(short = "l", long = "log-config", help = "Log config file path")]
    log_config_path: Option<String>,

    #[structopt(short = "a", long = "auth-bin", help = "Authentication BIN file path")]
    auth_bin_path: String,
}

#[derive(new, Debug, PartialEq, Deserialize, Serialize)]
struct SaltEncryptedPayloadGroup {
    salt: CString,
    encrypted_hashhex_payload_b64: CString,
}

#[derive(new, Debug, PartialEq, Deserialize, Serialize)]
struct AuthExchanger {
    exchanger: HashMap<String, SaltEncryptedPayloadGroup>,
    cipher_algo_name: String,
}

fn run() -> Result<()> {
    let config = MainConfig::from_args();

    if let &Some(ref log_config_path) = &config.log_config_path {
        log4rs::init_file(log_config_path, Default::default())
            .chain_err(|| format!("Unable to initialize log4rs logger with the given config file at '{}'", log_config_path))?;
    } else {
        simple_logger::init()
            .chain_err(|| "Unable to initialize default logger")?;
    }

    let fbuf = FileBuffer::open(&config.auth_bin_path)
        .chain_err(|| format!("Unable to open '{}'", config.auth_bin_path))?;

    let mut de = Deserializer::new(&fbuf[..]);

    let auth_exchanger: AuthExchanger = Deserialize::deserialize(&mut de)
        .chain_err(|| format!("Unable to deserialize content from '{}' into AuthExchanger", config.auth_bin_path))?;

    Ok(())
}

fn main() {
    match run() {
        Ok(_) => {
            info!("Program completed!");
            process::exit(0)
        },

        Err(ref e) => {
            error!("Error: {}", e);

            for e in e.iter().skip(1) {
                error!("> Caused by: {}", e);
            }

            process::exit(1);
        },
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_new_exchanger() {
        let test_new_exchanger_impl = |write_path: &str| -> Result<()> {
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

            let auth_exchanger = AuthExchanger::new(
                hm, "aes256".to_owned());

            auth_exchanger.serialize(&mut Serializer::new(&mut buf))
                .chain_err(|| "Unable to serialize")?;

            file::put(write_path, &buf[..])
                .chain_err(|| "File write open error")
        };

        const WRITE_PATH: &'static str = "test_new_exchanger.bin";

        let test_do_new_exchanger_test = test_new_exchanger_impl(WRITE_PATH);
        assert!(test_do_new_exchanger_test.is_ok());
        
        let do_remove_file = fs::remove_file(WRITE_PATH);
        assert!(do_remove_file.is_ok());
    }

    #[test]
    fn test_hello_world_exchange() {
        let buf = [
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

        let mut de = Deserializer::new(&buf[..]);

        let auth_exchanger: AuthExchanger = Deserialize::deserialize(&mut de)
            .expect("Unable to deserialize buffer content into AuthExchanger");

        let salt_with_encrypted_hashhex_payload_b64 = &auth_exchanger.exchanger["hello"];
        let salt = salt_with_encrypted_hashhex_payload_b64.salt.as_bytes();
        let encrypted_hashhex_payload_b64 = salt_with_encrypted_hashhex_payload_b64.encrypted_hashhex_payload_b64.as_bytes();

        const HASH_ITERATIONS: u32 = 4096;
        const SECRET: &'static str = "world";
        let secret = SECRET.as_bytes();
        
        // need to hash the password first
        let mut hashed_secret = [0u8; digest::SHA1_OUTPUT_LEN];

        pbkdf2::derive(
            &digest::SHA1,
            HASH_ITERATIONS,
            salt,
            secret,
            &mut hashed_secret);

        let hashed_secret_hex = hashed_secret.to_hex().to_lowercase();

        // payload is in base64, so convert it back into binary first before decryption
        let encrypted_hashhex_payload = {
            let mut buf = Vec::new();

            base64::decode_config_buf(encrypted_hashhex_payload_b64, base64::MIME, &mut buf)
                .expect("base64 decoding failed");

            buf
        };

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
        let aes_algo = Cipher::aes_256_cbc();

        let key_iv = pkcs5::bytes_to_key(
            aes_algo,
            MessageDigest::md5(),
            hashed_secret_hex.as_bytes(),
            Some(aes_salt),
            MD_ITERATIONS).unwrap();
        
        let iv_opt = match &key_iv.iv {
            &Some(ref iv) => Some(iv.as_slice()),
            &None => None,
        };

        let hashhex_payload_res = symm::decrypt(
            aes_algo,
            &key_iv.key,
            iv_opt,
            encrypted_hashhex_payload.as_slice());

        if let &Err(ref e) = &hashhex_payload_res {
            println!("Error: {}", e);
        }

        assert!(hashhex_payload_res.is_ok());

        let hashhex_payload = hashhex_payload_res.unwrap();

        // multiply by 2 because hex has twice the length from binary u8 representation
        const SHA1_DIGEST_HEX_COUNT: usize = digest::SHA1_OUTPUT_LEN * 2;

        // need to convert hex back into binary for the originally attached hash value derived from the payload
        let payload_hashhex = &hashhex_payload[0..SHA1_DIGEST_HEX_COUNT];
        let payload_hash = str::from_utf8(payload_hashhex).unwrap().from_hex().unwrap();

        let payload = &hashhex_payload[SHA1_DIGEST_HEX_COUNT..];

        let verify_res = pbkdf2::verify(
            &digest::SHA1,
            HASH_ITERATIONS,
            salt,
            payload,
            payload_hash.as_slice());

        assert!(verify_res.is_ok());
    }
}