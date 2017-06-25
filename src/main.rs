#![feature(rustc_private)]

mod auth;

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

use auth::{AuthMgmt, SaltEncryptedPayloadGroup};
use filebuffer::FileBuffer;
use openssl::hash::MessageDigest;
use openssl::pkcs5;
use openssl::symm::{self, Cipher};
use ring::{digest, pbkdf2};
use rmp_serde::{Deserializer, Serializer};
use serde::{Deserialize, Serialize};
use serialize::hex::{FromHex, ToHex};
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

    let auth_mgmt: AuthMgmt = Deserialize::deserialize(&mut de)
        .chain_err(|| format!("Unable to deserialize content from '{}' into AuthMgmt", config.auth_bin_path))?;

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