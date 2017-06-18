#[macro_use]
extern crate derive_new;

#[macro_use]
extern crate error_chain;
extern crate file;
extern crate filebuffer;

#[macro_use]
extern crate log;
extern crate log4rs;
extern crate ring;
extern crate rmp;
extern crate rmp_serde;
extern crate serde;

#[macro_use]
extern crate serde_derive;
extern crate simple_logger;
extern crate structopt;

#[macro_use]
extern crate structopt_derive;

use filebuffer::FileBuffer;
use ring::{digest, hmac, pbkdf2};
use rmp_serde::{Deserializer, Serializer};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::CString;
use std::process;
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
    encrypted_payload_group: CString,
}

#[derive(new, Debug, PartialEq, Deserialize, Serialize)]
struct AuthExchanger {
    exchanger: HashMap<String, SaltEncryptedPayloadGroup>,
    cipher_algo_name: String,
}

fn demo_writing(write_path: &str) -> Result<()> {
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
