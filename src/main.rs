#![feature(custom_derive, plugin, rustc_private)]
#![plugin(rocket_codegen)]

extern crate auth;

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
extern crate rmp_serde;
extern crate rocket;
extern crate rocket_contrib;
extern crate serde;

#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate serialize;
extern crate simple_logger;
extern crate structopt;

#[macro_use]
extern crate structopt_derive;

use auth::auth::AuthMgmt;
use rmp_serde::Deserializer;
use serde::{Deserialize, Serialize};
use filebuffer::FileBuffer;
use ring::{digest, pbkdf2};
use rocket::config::{Config, Environment};
use rocket::http::{Cookie, Cookies};
use rocket::request::Form;
use rocket::response::{Flash, NamedFile, Redirect};
use rocket::State;
use rocket_contrib::JSON;
use serialize::hex::ToHex;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Mutex;
use structopt::StructOpt;

// constants
const TOKEN_NAME: &'static str = "token";

const RESP_OK: &'static str = "ok";
const RESP_INVALID_TOKEN: &'static str = "invalid token";
const RESP_NO_SUCH_COOKIE: &'static str = "no such cookie";
const RESP_NO_SUCH_CREDENTIALS: &'static str = "no such credentials";
const RESP_NOT_ALLOWED: &'static str = "not allowed";
const RESP_UNABLE_TO_CONVERT_TO_JSON: &'static str = "unable to convert to JSON";
const RESP_UNABLE_TO_LOCK: &'static str = "unable to lock";
const RESP_UNABLE_TO_PROCESS: &'static str = "unable to process";
const RESP_UNABLE_TO_WRITE_FILE: &'static str = "unable to write file";

const INDEX_FILENAME: &'static str = "index.html";
const WEB_INDEX_PATH: &'static str = "/site/index.html";
const WEB_OVERVIEW_PATH: &'static str = "/site/overview.html";

#[derive(new, Debug, PartialEq, Deserialize, Serialize)]
struct RespStatus {
    status: String,
}

#[derive(new, Debug, PartialEq, Deserialize, Serialize)]
#[serde(bound(deserialize = ""))]
struct RespStatusWithData<T>
where T: for<'de_inner> Deserialize<'de_inner> + Serialize {
    status: String,
    data: Option<T>,
}

impl<T> From<RespStatus> for RespStatusWithData<T>
where T: for<'de_inner> serde::Deserialize<'de_inner> + Serialize {
    fn from(e: RespStatus) -> RespStatusWithData<T> {
        RespStatusWithData::new(e.status, None)
    }
}

impl<T> RespStatusWithData<T>
where T: for<'de_inner> Deserialize<'de_inner> + Serialize {
    fn ok(v: T) -> RespStatusWithData<T> {
        RespStatusWithData {
            status: RESP_OK.to_owned(),
            data: Some(v),
        }
    }
}

#[derive(Debug, Clone, FromForm, PartialEq, Deserialize, Serialize)]
struct Credentials {
    username: String,
    password: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
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
        errors {
            AuthErr(e: String) {
                description("authentication error")
                display("authentication error: {}", e)
            }
            SyncPoisonError(e: String) {
                description("poison error")
                display("poison error: {}", e)
            }
        }
    }
}

impl From<auth::auth::AuthErr> for Error {
    fn from(e: auth::auth::AuthErr) -> Self {
        Self::from_kind(ErrorKind::AuthErr(format!("{:?}", e)))
    }
}

impl<T> From<std::sync::PoisonError<T>> for Error {
    fn from(e: std::sync::PoisonError<T>) -> Self {
        use std::error::Error;
        Self::from_kind(ErrorKind::SyncPoisonError(e.description().to_string()))
    }
}

// change between OxxxAdminTaskCredentials and E2AdminTaskCredentials
type User = String;
type Token = String;

type AdminTaskCredentials = OxxxAdminTaskCredentials;
type IoError = std::io::Error;
type UserMappings = HashMap<User, Token>;
type TokenMappings = HashMap<Token, AdminTaskCredentials>;
type MAuthMgmt = Mutex<AuthMgmt>;
type MMappings = Mutex<(UserMappings, TokenMappings)>;
type StdResult<T, E> = std::result::Result<T, E>;

#[derive(Debug, PartialEq, Deserialize, Serialize)]
struct UserPwCreds {
    username: String,
    password: String,
    creds: AdminTaskCredentials,
}

macro_rules! json_opt {
    ($r:expr, $s:expr) => {
        match $r {
            Some(r) => r,
            None => return JSON(RespStatus::new($s.to_owned()).into()),
        }
    }
}

macro_rules! json_bool {
    ($r:expr, $s:expr) => {
        if $r {
            $r
        } else {
            return JSON(RespStatus::new($s.to_owned()).into())
        }
    }
}

macro_rules! json_res {
    ($r:expr, $s:expr) => {
        match $r {
            Ok(r) => r,
            Err(_) => return JSON(RespStatus::new($s.to_owned()).into()),
        }
    }
}

macro_rules! json_check_ok {
    ($j:expr) => {
        match $j.status.as_str() {
            RESP_OK => $j,
            _ => return $j,
        }
    }
}

macro_rules! get_cred {
    ($cookies:expr, $token_mappings:expr) => {{
        let token = json_opt!($cookies.get(TOKEN_NAME), RESP_NO_SUCH_COOKIE);
        let creds = json_opt!($token_mappings.get(token.value()), RESP_INVALID_TOKEN);
        creds.clone()
    }}
}

fn compress_opt_bool(opt: Option<bool>) -> bool {
    match opt {
        Some(v) => v,
        None => false,
    }
}

fn write_auth_to_file(auth_mgmt: &AuthMgmt, config: &MainConfig) -> JSON<RespStatus> {
    let auth_mgmt_str = json_res!(serde_json::to_string(auth_mgmt), RESP_UNABLE_TO_CONVERT_TO_JSON);
    json_res!(file::put(&config.auth_bin_path, auth_mgmt_str.as_bytes()), RESP_UNABLE_TO_WRITE_FILE);
    JSON(RespStatus::new(RESP_OK.to_owned()))
}

#[post("/add_mapping", data = "<user_pw_creds>")]
fn add_mapping(auth_mgmt: State<MAuthMgmt>, config: State<MainConfig>, mappings: State<MMappings>, cookies: Cookies, user_pw_creds: JSON<UserPwCreds>) -> JSON<RespStatus> {
    let (_, ref token_mappings) = *json_res!(mappings.lock(), RESP_UNABLE_TO_LOCK);
    let admin_task_creds = get_cred!(cookies, token_mappings);
    let add_users = compress_opt_bool(admin_task_creds.add_users);

    // check for permission
    json_bool!(add_users, RESP_NOT_ALLOWED);

    // perform the actual adding of credentials here
    let mut auth_mgmt = json_res!(auth_mgmt.lock(), RESP_UNABLE_TO_LOCK);
    json_res!(auth_mgmt.add(user_pw_creds.username.clone(), user_pw_creds.password.clone(), &user_pw_creds.creds), RESP_UNABLE_TO_PROCESS);
    JSON(RespStatus::new(RESP_OK.to_owned()));

    write_auth_to_file(&*auth_mgmt, &*config)
}

fn generic_delete_mapping_impl<T, E, F>(auth_mgmt: &State<MAuthMgmt>, config: &State<MainConfig>, mappings: &State<MMappings>, cookies: &Cookies, username: &str, del_fn: F) -> JSON<RespStatus> 
    where F: FnOnce(&mut AuthMgmt) -> StdResult<T, E> {

    let (ref mut user_mappings, ref mut token_mappings) = *json_res!(mappings.lock(), RESP_UNABLE_TO_LOCK);

    let admin_task_creds = get_cred!(cookies, token_mappings);
    let delete_users = compress_opt_bool(admin_task_creds.delete_users);

    // check for permission
    json_bool!(delete_users, RESP_NOT_ALLOWED);

    // perform the actual delete here
    let mut auth_mgmt = json_res!(auth_mgmt.lock(), RESP_UNABLE_TO_LOCK);
    json_res!(del_fn(&mut *auth_mgmt), RESP_UNABLE_TO_PROCESS);

    // remove the login mappings if available
    // need to clone to prevent shared and mutable borrow
    let logged_token = user_mappings.get(username).cloned();

    if let Some(logged_token) = logged_token {
        let _ = token_mappings.remove(&logged_token);
        let _ = user_mappings.remove(username);
    }

    write_auth_to_file(&*auth_mgmt, &*config)
}

#[delete("/delete_mapping", data = "<creds>")]
fn delete_mapping(auth_mgmt: State<MAuthMgmt>, config: State<MainConfig>, mappings: State<MMappings>, cookies: Cookies, creds: JSON<Credentials>) -> JSON<RespStatus> {
    generic_delete_mapping_impl(&auth_mgmt, &config, &mappings, &cookies, &creds.username, |auth_mgmt| auth_mgmt.delete(&creds.username, &creds.password))
}

fn force_delete_mapping_impl(auth_mgmt: &State<MAuthMgmt>, config: &State<MainConfig>, mappings: &State<MMappings>, cookies: &Cookies, username: &str) -> JSON<RespStatus> {
    generic_delete_mapping_impl(auth_mgmt, config, mappings, cookies, username, |auth_mgmt| auth_mgmt.force_delete(username))
}

#[delete("/force_delete_mapping", data = "<username>")]
fn force_delete_mapping(auth_mgmt: State<MAuthMgmt>, config: State<MainConfig>, mappings: State<MMappings>, cookies: Cookies, username: String) -> JSON<RespStatus> {
    force_delete_mapping_impl(&auth_mgmt, &config, &mappings, &cookies, &username)
}

#[put("/update_mapping", data = "<user_pw_creds>")]
fn update_mapping(auth_mgmt: State<MAuthMgmt>, config: State<MainConfig>, mappings: State<MMappings>, cookies: Cookies, user_pw_creds: JSON<UserPwCreds>) -> JSON<RespStatus> {
    let (_, ref token_mappings) = *json_res!(mappings.lock(), RESP_UNABLE_TO_LOCK);
    let admin_task_creds = get_cred!(cookies, token_mappings);
    let update_users = compress_opt_bool(admin_task_creds.update_users);

    // check for permission
    json_bool!(update_users, RESP_NOT_ALLOWED);

    // perform the actual update here
    let mut auth_mgmt = json_res!(auth_mgmt.lock(), RESP_UNABLE_TO_LOCK);
    json_res!(auth_mgmt.update(&user_pw_creds.username, &user_pw_creds.password, &user_pw_creds.creds), RESP_UNABLE_TO_PROCESS);

    // no need to change the login mappings because this operation ensures that the password remains the same
    write_auth_to_file(&*auth_mgmt, &*config)
}

#[put("/force_update_mapping", data = "<user_pw_creds>")]
fn force_update_mapping(auth_mgmt: State<MAuthMgmt>, config: State<MainConfig>, mappings: State<MMappings>, cookies: Cookies, user_pw_creds: JSON<UserPwCreds>) -> JSON<RespStatus> {
    // delete then followed by add
    json_check_ok!(force_delete_mapping_impl(&auth_mgmt, &config, &mappings, &cookies, &user_pw_creds.username));
    add_mapping(auth_mgmt, config, mappings, cookies, user_pw_creds)
}

fn login_exchange_impl(auth_mgmt: &State<MAuthMgmt>, creds: &Credentials) -> Result<AdminTaskCredentials> {
    let auth_mgmt = auth_mgmt.lock()?;
    let admin_task_creds = auth_mgmt.exchange(&creds.username, &creds.password)?;
    Ok(admin_task_creds)
}

fn generate_hash(creds: &Credentials) -> String {
    const HASH_ITERATIONS: u32 = 1024;

    // generate the salt in a fixed manner based on username only
    let salt = creds.username.as_bytes();
    let secret = creds.password.as_bytes();
    let mut hashed_secret = [0u8; digest::SHA256_OUTPUT_LEN];

    pbkdf2::derive(
        &digest::SHA256,
        HASH_ITERATIONS,
        salt,
        secret,
        &mut hashed_secret);

    hashed_secret.to_hex().to_lowercase()
}

#[post("/login", data = "<creds>")]
fn login(auth_mgmt: State<MAuthMgmt>, mappings: State<MMappings>, mut cookies: Cookies, creds: Form<Credentials>) -> StdResult<Redirect, Flash<Redirect>> {
    let creds = creds.get();
    let admin_task_creds = login_exchange_impl(&auth_mgmt, creds);

    let admin_task_creds = admin_task_creds.map_err(|_| {
        Flash::error(Redirect::to(&format!("{}?failed=true", WEB_INDEX_PATH)), "Invalid credentials provided.")
    });

    admin_task_creds.and_then(|admin_task_creds| {
        // store into credential mappings + cookies
        match mappings.lock() {
            Ok(mut mappings) => {
                let (ref mut user_mappings, ref mut token_mappings) = *mappings;

                // generate the hash string
                let hash_str = generate_hash(creds);

                cookies.add(Cookie::new(TOKEN_NAME.to_owned(), hash_str.clone()));
                user_mappings.insert(creds.username.clone(), hash_str.clone());
                token_mappings.insert(hash_str, admin_task_creds.clone());

                Ok(Redirect::to(WEB_OVERVIEW_PATH))
            },
            Err(_) => {
                const ERR_MSG: &'static str = "Server error, unable to obtain mutex for credentials mapping.";
                error!("{}", ERR_MSG);
                Err(Flash::error(Redirect::to(WEB_INDEX_PATH), ERR_MSG))
            },
        }
    })
}

#[get("/info")]
fn info(mappings: State<MMappings>, cookies: Cookies) -> JSON<RespStatusWithData<AdminTaskCredentials>> {
    let (_, ref token_mappings) = *json_res!(mappings.lock(), RESP_UNABLE_TO_LOCK);
    let admin_task_creds = get_cred!(cookies, token_mappings);

    JSON(RespStatusWithData::ok(admin_task_creds.clone()))
}

#[post("/exchange", data = "<creds>")]
fn exchange(auth_mgmt: State<MAuthMgmt>, creds: JSON<Credentials>) -> JSON<RespStatusWithData<AdminTaskCredentials>> {
    match login_exchange_impl(&auth_mgmt, &creds) {
        Ok(admin_task_creds) => JSON(RespStatusWithData::ok(admin_task_creds)),
        Err(_) => JSON(RespStatusWithData::new(RESP_NO_SUCH_CREDENTIALS.to_owned(), None)),
    }
}

#[get("/site/<path..>")]
fn get_file(config: State<MainConfig>, path: PathBuf) -> StdResult<NamedFile, IoError> {
    NamedFile::open(Path::new(&config.site_path).join(path))
}

#[get("/")]
fn index(config: State<MainConfig>) -> StdResult<NamedFile, IoError> {
    NamedFile::open(Path::new(&config.site_path).join(INDEX_FILENAME))
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

    #[structopt(short = "s", long = "site-path", help = "Site root path of HTTP hosting", default_value = "site")]
    site_path: String,
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

    let auth_mgmt: AuthMgmt = match fs::metadata(&config.auth_bin_path) {
        Ok(_) => {
            let fbuf = FileBuffer::open(&config.auth_bin_path)
                .chain_err(|| format!("Unable to open '{}'", config.auth_bin_path))?;

            let mut de = Deserializer::new(&fbuf[..]);

            Deserialize::deserialize(&mut de)
                .chain_err(|| format!("Unable to deserialize content from '{}' into AuthMgmt", config.auth_bin_path))?
        },
        Err(_) => {
            info!("Authentication file at '{}' does not exist, creating a new authentication management...", config.auth_bin_path);

            // creates a default admin with only permissions to do admin stuff
            let mut auth_mgmt = AuthMgmt::new();

            let add_res = auth_mgmt.add("admin".to_owned(), "admin".to_owned(),
                &AdminTaskCredentials {
                    admin_credentials: None,
                    sensor_id: "".to_owned(),
                    start: false,
                    stop: false,
                    shutdown: false,
                    erase: false,
                    config_read: false,
                    config_update: false,
                    initiated_bit: false,
                    continuous_bit: false,
                    explore: false,
                    verify_oxxx_nxxs: false,
                    import_oxxx_nxxs: false,
                    export_oxxx_nxxs: false,
                    oxxx_nxxs_read: false,
                    oxxx_nxxs_schema_read: false,
                    oxxx_nxxs_update: false,
                    oxxx_nxxs_delete: false,
                    oxxx_tasks_read: false,
                    oxxx_tasks_schema_read: false,
                    oxxx_ref_lxx_read: false,
                    oxxx_red_lxx_update: false,
                    get_users: Some(true),
                    add_users: Some(true),
                    update_users: Some(true),
                    delete_users: Some(true),
                });

            if let Err(_) = add_res {
                bail!("Unable to add default admin credentials");
            }

            auth_mgmt
        },
    };

    let rocket_config = Config::build(Environment::Production)
        .address(config.address.clone())
        .port(config.port)
        .finalize()
        .chain_err(|| "Unable to create the custom rocket configuration!")?;

    rocket::custom(rocket_config, false)
        .manage(config)
        .manage(Mutex::new(auth_mgmt))
        .manage(Mutex::new((UserMappings::new(), TokenMappings::new())))
        .mount("/", routes![
            index, get_file,
            login, exchange, info,
            add_mapping, delete_mapping, force_delete_mapping, update_mapping, force_update_mapping]).launch();

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