#![feature(rustc_private)]

extern crate base64;

#[macro_use]
extern crate derive_new;
extern crate file;
extern crate openssl;
extern crate ring;
extern crate rmp_serde;
extern crate serde;

#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate serialize;

pub mod auth;