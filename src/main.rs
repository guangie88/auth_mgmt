#![feature(custom_derive, plugin, rustc_private)]
#![plugin(rocket_codegen)]

extern crate auth_mgmt;
extern crate bidir_map;

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

mod util;

use auth_mgmt::AuthMgmt;
use rmp_serde::{Deserializer, Serializer};
use serde::{Deserialize, Serialize};
use filebuffer::FileBuffer;
use ring::{digest, pbkdf2};
use rocket::config::{Config, Environment};
use rocket::http::{Cookie, Cookies};
use rocket::http::uri::URI;
use rocket::request::Form;
use rocket::response::{NamedFile, Redirect};
use rocket::State;
use rocket_contrib::{JSON, Template};
use serialize::hex::ToHex;
use std::io;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Mutex;
use structopt::StructOpt;

use util::*;
use errors::ResultExt;

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
    let mut buf = Vec::new();
    json_res!(auth_mgmt.serialize(&mut Serializer::new(&mut buf)), RESP_UNABLE_TO_CONVERT_TO_MSGPACK);
    
    json_res!(file::put(&config.auth_bin_path, &buf), RESP_UNABLE_TO_WRITE_FILE);
    JSON(RespStatus::ok())
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
    JSON(RespStatus::ok());

    write_auth_to_file(&*auth_mgmt, &*config)
}

fn generic_delete_mapping_impl<T, E, F>(auth_mgmt: &State<MAuthMgmt>, config: &State<MainConfig>, mappings: &State<MMappings>, cookies: &Cookies, username: &str, del_fn: F) -> JSON<RespStatus> 
    where F: FnOnce(&mut AuthMgmt) -> Result<T, E> {

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
    let logged_token = user_mappings.get_by_first(username).cloned();

    if let Some(logged_token) = logged_token {
        let _ = token_mappings.remove(&logged_token);
        let _ = user_mappings.remove_by_first(username);
    }

    write_auth_to_file(&*auth_mgmt, &*config)
}

#[delete("/delete_mapping", data = "<creds>")]
fn delete_mapping(auth_mgmt: State<MAuthMgmt>, config: State<MainConfig>, mappings: State<MMappings>, cookies: Cookies, creds: JSON<Credentials>) -> JSON<RespStatus> {
    generic_delete_mapping_impl(&auth_mgmt, &config, &mappings, &cookies, &creds.username, |auth_mgmt| auth_mgmt.delete(&creds.username, &creds.password))
}

fn force_delete_mappings_impl(auth_mgmt: &State<MAuthMgmt>, config: &State<MainConfig>, mappings: &State<MMappings>, cookies: &Cookies, username: &str) -> JSON<RespStatus> {
    generic_delete_mapping_impl(auth_mgmt, config, mappings, cookies, username, |auth_mgmt| auth_mgmt.force_delete(username))
}

#[delete("/force_delete_mappings", data = "<usernames>")]
fn force_delete_mappings(auth_mgmt: State<MAuthMgmt>, config: State<MainConfig>, mappings: State<MMappings>, cookies: Cookies, usernames: JSON<Vec<String>>) -> JSON<RespStatus> {
    usernames.iter().fold(JSON(RespStatus::ok()), |prev_status, username| {
        if prev_status.status == RESP_OK {
            force_delete_mappings_impl(&auth_mgmt, &config, &mappings, &cookies, &username)
        } else {
            prev_status
        }
    })
}

#[put("/update_mapping", data = "<user_pw_creds>")]
fn update_mapping(auth_mgmt: State<MAuthMgmt>, config: State<MainConfig>, mappings: State<MMappings>, cookies: Cookies, user_pw_creds: JSON<UserPwCreds>) -> JSON<RespStatus> {
    let (ref user_mappings, ref mut token_mappings) = *json_res!(mappings.lock(), RESP_UNABLE_TO_LOCK);
    let admin_task_creds = get_cred!(cookies, token_mappings);
    let update_users = compress_opt_bool(admin_task_creds.update_users);

    // check for permission
    json_bool!(update_users, RESP_NOT_ALLOWED);

    // perform the actual update here
    let mut auth_mgmt = json_res!(auth_mgmt.lock(), RESP_UNABLE_TO_LOCK);
    json_res!(auth_mgmt.update(&user_pw_creds.username, &user_pw_creds.password, &user_pw_creds.creds), RESP_UNABLE_TO_PROCESS);

    // may need to re-cache the mappings if the entry exists
    let token = user_mappings.get_by_first(&user_pw_creds.username);

    if let Some(token) = token {
        // updates the updated payload
        let _ = token_mappings.insert(token.to_owned(), user_pw_creds.creds.clone());
    }

    // no need to change the login mappings because this operation ensures that the password remains the same
    write_auth_to_file(&*auth_mgmt, &*config)
}

#[put("/force_update_mapping", data = "<user_pw_creds>")]
fn force_update_mapping(auth_mgmt: State<MAuthMgmt>, config: State<MainConfig>, mappings: State<MMappings>, cookies: Cookies, user_pw_creds: JSON<UserPwCreds>) -> JSON<RespStatus> {
    // delete then followed by add
    json_check_ok!(force_delete_mappings_impl(&auth_mgmt, &config, &mappings, &cookies, &user_pw_creds.username));
    add_mapping(auth_mgmt, config, mappings, cookies, user_pw_creds)
}

fn login_exchange_impl(auth_mgmt: &State<MAuthMgmt>, creds: &Credentials) -> errors::Result<AdminTaskCredentials> {
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
fn login(auth_mgmt: State<MAuthMgmt>, mappings: State<MMappings>, mut cookies: Cookies, creds: Form<Credentials>) -> Result<Redirect, Redirect> {
    let creds = creds.get();
    let admin_task_creds = login_exchange_impl(&auth_mgmt, creds);

    let admin_task_creds = admin_task_creds.map_err(|_| {
        Redirect::to(&format!("{}?fail", WEB_INDEX_PATH))
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
                error!("Server error, unable to obtain mutex for credentials mapping.");
                Err(Redirect::to(WEB_INDEX_PATH))
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

#[get("/get_users")]
fn get_users(auth_mgmt: State<MAuthMgmt>) -> JSON<RespStatusWithData<Vec<String>>> {
    let auth_mgmt = json_res!(auth_mgmt.lock(), RESP_UNABLE_TO_LOCK);
    
    JSON(RespStatusWithData::ok(auth_mgmt.get_keys()
        .into_iter()
        .cloned()
        .collect()))
}

#[get("/get_default_creds")]
fn get_default_creds() -> JSON<RespStatusWithData<UserPwCreds>> {
    JSON(RespStatusWithData::ok(UserPwCreds::default()))
}

#[get("/overview")]
fn overview(mappings: State<MMappings>, cookies: Cookies) -> Result<Template, Redirect> {
    let token = cookies.get(TOKEN_NAME)
        .ok_or_else(|| Redirect::to(&format!("{}?fail", WEB_INDEX_PATH)))?;

    let redirect = Redirect::to(&format!("{}", WEB_INDEX_PATH));

    let mappings = match mappings.lock() {
        Ok(mappings) => mappings,
        Err(_) => return Err(redirect),
    };

    let (ref user_mappings, _) = *mappings;

    let username = user_mappings.get_by_second(token.value())
        .ok_or_else(|| redirect)?;

    let context = OverviewTemplateContext::new(username.to_owned());
    Ok(Template::render("overview", &context))
}

#[get("/")]
fn index(uri: &URI) -> Template {
    let query = uri.query();

    let fail = match query {
        Some("fail") => true,
        _ => false,
    };

    let context = IndexTemplateContext::new(fail);
    Template::render("index", &context)
}

#[get("/images/<path..>")]
fn get_images(path: PathBuf) -> Result<NamedFile, io::Error> {
    NamedFile::open(Path::new("images").join(path))
}

#[get("/js/<path..>")]
fn get_js(path: PathBuf) -> Result<NamedFile, io::Error> {
    NamedFile::open(Path::new("js").join(path))
}

#[get("/css/<path..>")]
fn get_css(path: PathBuf) -> Result<NamedFile, io::Error> {
    NamedFile::open(Path::new("css").join(path))
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

fn run() -> errors::Result<()> {
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
                    get_users: Some(true),
                    add_users: Some(true),
                    update_users: Some(true),
                    delete_users: Some(true),
                    ..Default::default()
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
        .attach(Template::fairing())
        .mount("/", routes![
            index, overview, get_images, get_js, get_css,
            login, get_users, get_default_creds, exchange, info,
            add_mapping, delete_mapping, force_delete_mappings, update_mapping, force_update_mapping]).launch();

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