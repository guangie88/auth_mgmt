#![feature(plugin)]
#![plugin(rocket_codegen)]

extern crate auth;

#[macro_use]
extern crate error_chain;
extern crate filebuffer;

#[macro_use]
extern crate log;
extern crate log4rs;
extern crate rmp_serde;
extern crate rocket;
extern crate rocket_contrib;
extern crate serde;

#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate simple_logger;
extern crate structopt;

#[macro_use]
extern crate structopt_derive;

use auth::auth::AuthMgmt;
use rmp_serde::Deserializer;
use serde::Deserialize;
use filebuffer::FileBuffer;
use rocket::config::{Config, Environment};
use rocket::response::NamedFile;
use rocket::State;
use rocket_contrib::JSON;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Mutex;
use structopt::StructOpt;

#[derive(Debug, PartialEq, Deserialize, Serialize)]
struct Credentials {
    username: String,
    password: String,
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct OxxxAdminTaskCredentials {
    #[serde(skip_serializing_if="Option::is_none")]
    admin_credentials: Option<Credentials>,
    sensor_id: String,

    // CommonRoleFlags
    start: bool,
    stop: bool,
    shutdown: bool,
    erase: bool,
    config_read: bool,
    config_update: bool,
    initiated_bit: bool,
    continuous_bit: bool,
    explore: bool,
    
    // OxxxOnlyRoleFlags
    verify_oxxx_nxxs: bool,
    import_oxxx_nxxs: bool,
    export_oxxx_nxxs: bool,
    oxxx_nxxs_read: bool,
    oxxx_nxxs_schema_read: bool,
    oxxx_nxxs_update: bool,
    oxxx_nxxs_delete: bool,
    oxxx_tasks_read: bool,
    oxxx_tasks_schema_read: bool,
    oxxx_ref_lxx_read: bool,
    oxxx_red_lxx_update: bool,

    // ImbuedPayload
    #[serde(skip_serializing_if="Option::is_none")]
    get_users: Option<bool>,
    #[serde(skip_serializing_if="Option::is_none")]
    add_users: Option<bool>,
    #[serde(skip_serializing_if="Option::is_none")]
    update_users: Option<bool>,
    #[serde(skip_serializing_if="Option::is_none")]
    delete_users: Option<bool>,
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct E2AdminTaskCredentials {
    #[serde(skip_serializing_if="Option::is_none")]
    admin_credentials: Option<Credentials>,
    sensor_id: String,
    fx_credentials: Credentials,

    // CommonRoleFlags
    start: bool,
    stop: bool,
    shutdown: bool,
    erase: bool,
    config_read: bool,
    config_update: bool,
    initiated_bit: bool,
    continuous_bit: bool,
    explore: bool,

    // VxxOnlyRoleFlags
    verify_vxx_nxxs: bool,
    import_vxx_nxxs: bool,
    export_vxx_nxxs: bool,
    send_to_merge_nxx: bool,
    send_to_rename_nxx: bool,
    send_to_prioritize_nxx: bool,
    vxx_nxxs_read: bool,
    vxx_nxxs_update: bool,
    vxx_nxxs_delete: bool,
    vxx_tasks_read: bool,
    recv_production_result: bool,
    send_bxxxx_fxxxs: bool,
    send_vvv_production_resubmit_request: bool,
    send_ww_stxxxing_production_request: bool,
    
    // OxxxOnlyRoleFlags
    verify_oxxx_nxxs: bool,
    import_oxxx_nxxs: bool,
    export_oxxx_nxxs: bool,
    oxxx_nxxs_read: bool,
    oxxx_nxxs_schema_read: bool,
    oxxx_nxxs_update: bool,
    oxxx_nxxs_delete: bool,
    oxxx_tasks_read: bool,
    oxxx_tasks_schema_read: bool,
    oxxx_ref_lxx_read: bool,
    oxxx_red_lxx_update: bool,

    // ImbuedPayload
    #[serde(skip_serializing_if="Option::is_none")]
    get_users: Option<bool>,
    #[serde(skip_serializing_if="Option::is_none")]
    add_users: Option<bool>,
    #[serde(skip_serializing_if="Option::is_none")]
    update_users: Option<bool>,
    #[serde(skip_serializing_if="Option::is_none")]
    delete_users: Option<bool>,
}

mod errors {
    error_chain! {
        errors {}
    }
}

// change between OxxxAdminTaskCredentials and E2AdminTaskCredentials
type AdminTaskCredentials = OxxxAdminTaskCredentials;
type IoError = std::io::Error;
type MAuthMgmt = Mutex<AuthMgmt>;
type StdResult<T, E> = std::result::Result<T, E>;

#[get("/add_mapping")]
fn add_mapping(_auth_mgmt: State<MAuthMgmt>) -> StdResult<(), ()> {
    unimplemented!();
}

#[get("/delete_mapping")]
fn delete_mapping(_auth_mgmt: State<MAuthMgmt>) -> StdResult<(), ()> {
    unimplemented!();
}

#[get("/force_delete_mapping")]
fn force_delete_mapping(_auth_mgmt: State<MAuthMgmt>) -> StdResult<(), ()> {
    unimplemented!();
}

#[get("/update_mapping")]
fn update_mapping(_auth_mgmt: State<MAuthMgmt>) -> StdResult<(), ()> {
    unimplemented!();
}

#[get("/exchange")]
fn exchange(_auth_mgmt: State<MAuthMgmt>) -> StdResult<JSON<AdminTaskCredentials>, ()> {
    unimplemented!();
}

#[get("/files/<path..>")]
fn get_file(path: PathBuf) -> StdResult<NamedFile, IoError> {
    NamedFile::open(Path::new("files/").join(path))
}

#[derive(StructOpt, Debug)]
#[structopt(name = "Authentication Management", about = "Program to perform authentication management.")]
struct MainConfig {
    #[structopt(short = "l", long = "log-config", help = "Log config file path")]
    log_config_path: Option<String>,

    #[structopt(short = "a", long = "address", help = "Interface address to host", default_value = "0.0.0.0")]
    address: String,

    #[structopt(short = "p", long = "port", help = "Port to host")]
    port: u16,

    #[structopt(short = "b", long = "auth-bin", help = "Authentication BIN file path")]
    auth_bin_path: String,
}

use errors::*;

fn run() -> Result<()> {
    let config = MainConfig::from_args();

    if let &Some(ref log_config_path) = &config.log_config_path {
        log4rs::init_file(log_config_path, Default::default())
            .chain_err(|| format!("Unable to initialize log4rs logger with the given config file at '{}'", log_config_path))?;
    } else {
        simple_logger::init()
            .chain_err(|| "Unable to initialize default logger")?;
    }

    let auth_mgmt: AuthMgmt = {
        let fbuf = FileBuffer::open(&config.auth_bin_path)
            .chain_err(|| format!("Unable to open '{}'", config.auth_bin_path))?;

        let mut de = Deserializer::new(&fbuf[..]);

        Deserialize::deserialize(&mut de)
            .chain_err(|| format!("Unable to deserialize content from '{}' into AuthMgmt", config.auth_bin_path))?
    };

    let rocket_config = Config::build(Environment::Production)
        .address(config.address.clone())
        .port(config.port)
        .finalize()
        .chain_err(|| "Unable to create the custom rocket configuration!")?;

    rocket::custom(rocket_config, false)
        .manage(config)
        .manage(Mutex::new(auth_mgmt))
        .mount("/", routes![
            add_mapping, delete_mapping, force_delete_mapping, update_mapping, exchange,
            get_file]).launch();

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