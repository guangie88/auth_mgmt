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

use auth_mgmt::{AuthErr, AuthMgmt};
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
use rocket_contrib::{Json, Template};
use serialize::hex::ToHex;
use std::io;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Mutex;
use structopt::StructOpt;

use util::*;
use errors::ResultExt;

macro_rules! get_token {
    ($cookies:expr) => {{
        match $cookies.get(TOKEN_NAME) {
            Some(token) => token,
            None => bail!("No token cookie!"),
        }
    }}
}

macro_rules! get_username_from_token {
    ($token:expr, $user_mappings:expr) => {{
        match $user_mappings.get_by_second($token.value()) {
            Some(username) => username,
            None => bail!("No valid username from given token!"),
        }
    }}
}

macro_rules! get_payload_creds_from_token {
    ($token:expr, $token_mappings:expr) => {{
        let creds = match $token_mappings.get($token.value()) {
            Some(creds) => creds,
            None => bail!("Unable to get credentials payload for token from cookie!"),
        };

        creds.clone()
    }}
}

macro_rules! get_payload_creds {
    ($cookies:expr, $token_mappings:expr) => {{
        let token = get_token!($cookies);
        get_payload_creds_from_token!(token, $token_mappings)
    }}
}

macro_rules! check_perm {
    ($perm:expr) => {{
        if !$perm {
            bail!("Permission not granted!");
        }
    }}
}

fn into_json_resp_status<T>(r: errors::Result<T>) -> Json<RespStatus> {
    let status = match r {
        Ok(_) => RespStatus::ok(),
        Err(e) => RespStatus::new(format!("{}", e)),
    };

    Json(status)
}

fn into_json_resp_status_with_data<T>(r: errors::Result<T>) -> Json<RespStatusWithData<T>>
where T: for<'de_inner> Deserialize<'de_inner> + Serialize {
    let status_with_data = match r {
        Ok(r) => RespStatusWithData::ok(r),
        Err(e) => RespStatusWithData::err(format!("{}", e)),
    };

    Json(status_with_data)
}

fn compress_opt_bool(opt: Option<bool>) -> bool {
    match opt {
        Some(v) => v,
        None => false,
    }
}

fn write_auth_to_file(auth_mgmt: &AuthMgmt, config: &MainConfig) -> errors::Result<()> {
    let mut buf = Vec::new();

    auth_mgmt.serialize(&mut Serializer::new(&mut buf))
        .chain_err(|| "Unable to serialize auth management value!")?;
    
    file::put(&config.auth_bin_path, &buf)
        .chain_err(|| format!("Unable to serialize into auth bin file at {}", config.auth_bin_path))?;

    Ok(())
}

fn add_mapping_impl(auth_mgmt: State<MAuthMgmt>, config: State<MainConfig>, mappings: State<MMappings>, cookies: Cookies, user_pw_creds: Json<UserPwCreds>) -> errors::Result<()> {
    let (_, ref token_mappings) = *mappings.lock()?;
    let admin_task_creds = get_payload_creds!(cookies, token_mappings);
    let add_users = compress_opt_bool(admin_task_creds.allowed_roles.add_users);

    // check for permission
    check_perm!(add_users);

    // perform the actual adding of credentials here
    let mut auth_mgmt = auth_mgmt.lock()?;
    auth_mgmt.add(user_pw_creds.username.clone(), user_pw_creds.password.clone(), &user_pw_creds.creds)?;

    write_auth_to_file(&auth_mgmt, &config)
}

#[post("/add_mapping", data = "<user_pw_creds>")]
fn add_mapping(auth_mgmt: State<MAuthMgmt>, config: State<MainConfig>, mappings: State<MMappings>, cookies: Cookies, user_pw_creds: Json<UserPwCreds>) -> Json<RespStatus> {
    into_json_resp_status(add_mapping_impl(auth_mgmt, config, mappings, cookies, user_pw_creds))
}

fn generic_delete_mapping_impl<T, F>(auth_mgmt: &State<MAuthMgmt>, config: &State<MainConfig>, mappings: &State<MMappings>, cookies: &Cookies, username: &str, del_fn: F) -> errors::Result<()> where
    F: FnOnce(&mut AuthMgmt) -> Result<T, AuthErr> {

    let (ref mut user_mappings, ref mut token_mappings) = *mappings.lock()?;

    let admin_task_creds = get_payload_creds!(cookies, token_mappings);
    let delete_users = compress_opt_bool(admin_task_creds.allowed_roles.delete_users);

    // check for permission
    check_perm!(delete_users);

    // perform the actual delete here
    let mut auth_mgmt = auth_mgmt.lock()?;
    del_fn(&mut auth_mgmt)?;

    // remove the login mappings if available
    // need to clone to prevent shared and mutable borrow
    let logged_token = user_mappings.get_by_first(username).cloned();

    if let Some(logged_token) = logged_token {
        let _ = token_mappings.remove(&logged_token);
        let _ = user_mappings.remove_by_first(username);
    }

    write_auth_to_file(&auth_mgmt, &config)
}

#[delete("/delete_mapping", data = "<creds>")]
fn delete_mapping(auth_mgmt: State<MAuthMgmt>, config: State<MainConfig>, mappings: State<MMappings>, cookies: Cookies, creds: Json<Credentials>) -> Json<RespStatus> {
    into_json_resp_status(generic_delete_mapping_impl(&auth_mgmt, &config, &mappings, &cookies, &creds.username, |auth_mgmt| auth_mgmt.delete(&creds.username, &creds.password)))
}

fn force_delete_mappings_impl(auth_mgmt: &State<MAuthMgmt>, config: &State<MainConfig>, mappings: &State<MMappings>, cookies: &Cookies, username: &str) -> errors::Result<()> {
    generic_delete_mapping_impl(auth_mgmt, config, mappings, cookies, username, |auth_mgmt| auth_mgmt.force_delete(username))
}

#[delete("/force_delete_mappings", data = "<usernames>")]
fn force_delete_mappings(auth_mgmt: State<MAuthMgmt>, config: State<MainConfig>, mappings: State<MMappings>, cookies: Cookies, usernames: Json<Vec<String>>) -> Json<RespStatus> {
    usernames.iter().fold(Json(RespStatus::ok()), |prev_status, username| {
        if prev_status.status == RESP_OK {
            into_json_resp_status(force_delete_mappings_impl(&auth_mgmt, &config, &mappings, &cookies, &username))
        } else {
            prev_status
        }
    })
}

fn update_mapping_impl(auth_mgmt: State<MAuthMgmt>, config: State<MainConfig>, mappings: State<MMappings>, cookies: Cookies, user_pw_creds: Json<UserPwCreds>) -> errors::Result<()> {
    let (ref user_mappings, ref mut token_mappings) = *mappings.lock()?;
    let admin_task_creds = get_payload_creds!(cookies, token_mappings);
    let update_users = compress_opt_bool(admin_task_creds.allowed_roles.update_users);

    // check for permission
    check_perm!(update_users);

    // perform the actual update here
    let mut auth_mgmt = auth_mgmt.lock()?;
    auth_mgmt.update(&user_pw_creds.username, &user_pw_creds.password, &user_pw_creds.creds)?;

    // may need to re-cache the mappings if the entry exists
    let token = user_mappings.get_by_first(&user_pw_creds.username);

    if let Some(token) = token {
        // updates the updated payload
        let _ = token_mappings.insert(token.to_owned(), user_pw_creds.creds.clone());
    }

    // no need to change the login mappings because this operation ensures that the password remains the same
    write_auth_to_file(&auth_mgmt, &config)
}

#[put("/update_mapping", data = "<user_pw_creds>")]
fn update_mapping(auth_mgmt: State<MAuthMgmt>, config: State<MainConfig>, mappings: State<MMappings>, cookies: Cookies, user_pw_creds: Json<UserPwCreds>) -> Json<RespStatus> {
    into_json_resp_status(update_mapping_impl(auth_mgmt, config, mappings, cookies, user_pw_creds))
}

fn force_update_mapping_impl(auth_mgmt: State<MAuthMgmt>, config: State<MainConfig>, mappings: State<MMappings>, cookies: Cookies, user_pw_creds: Json<UserPwCreds>) -> errors::Result<()> {
    // delete then followed by add
    force_delete_mappings_impl(&auth_mgmt, &config, &mappings, &cookies, &user_pw_creds.username)?;
    add_mapping_impl(auth_mgmt, config, mappings, cookies, user_pw_creds)
}

#[put("/force_update_mapping", data = "<user_pw_creds>")]
fn force_update_mapping(auth_mgmt: State<MAuthMgmt>, config: State<MainConfig>, mappings: State<MMappings>, cookies: Cookies, user_pw_creds: Json<UserPwCreds>) -> Json<RespStatus> {
    into_json_resp_status(force_update_mapping_impl(auth_mgmt, config, mappings, cookies, user_pw_creds))
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

fn change_password_impl(auth_mgmt: State<MAuthMgmt>, mappings: State<MMappings>, config: State<MainConfig>, mut cookies: Cookies, pw: Json<NewPassword>) -> errors::Result<()> {
    let new_password = &pw.new_password;
    let (ref mut user_mappings, ref mut token_mappings) = *mappings.lock()?;

    let (username, admin_task_creds) = {
        let token = get_token!(cookies);
        (get_username_from_token!(token, user_mappings).clone(), get_payload_creds_from_token!(token, token_mappings))
    };

    // delete and re-add using the new password
    let mut auth_mgmt = auth_mgmt.lock()?;
    auth_mgmt.force_delete(&username)?;
    auth_mgmt.add(username.clone(), new_password.clone(), &admin_task_creds)?;

    // update both mappings
    let new_creds = Credentials::new(username.clone(), new_password.clone());
    let new_hash_str = generate_hash(&new_creds);

    user_mappings.insert(username, new_hash_str.clone());
    token_mappings.insert(new_hash_str.clone(), admin_task_creds);

    // and update the cookies
    cookies.add(Cookie::new(TOKEN_NAME.to_owned(), new_hash_str.clone()));

    // also need to write into auth file
    write_auth_to_file(&auth_mgmt, &config)
}

#[post("/change_password", data = "<pw>")]
fn change_password(auth_mgmt: State<MAuthMgmt>, mappings: State<MMappings>, config: State<MainConfig>, cookies: Cookies, pw: Json<NewPassword>) -> Json<RespStatus> {
    into_json_resp_status(change_password_impl(auth_mgmt, mappings, config, cookies, pw))
}

fn info_impl(mappings: State<MMappings>, cookies: Cookies) -> errors::Result<AdminTaskCredentials> {
    let (_, ref token_mappings) = *mappings.lock()?;
    let admin_task_creds = get_payload_creds!(cookies, token_mappings);
    Ok(admin_task_creds.clone())
}

#[get("/info")]
fn info(mappings: State<MMappings>, cookies: Cookies) -> Json<RespStatusWithData<AdminTaskCredentials>> {
    into_json_resp_status_with_data(info_impl(mappings, cookies))
}

#[post("/exchange", data = "<creds>")]
fn exchange(auth_mgmt: State<MAuthMgmt>, creds: Json<Credentials>) -> Json<RespStatusWithData<AdminTaskCredentials>> {
    into_json_resp_status_with_data(login_exchange_impl(&auth_mgmt, &creds))
}

fn get_users_impl(auth_mgmt: State<MAuthMgmt>) -> errors::Result<Vec<String>> {
    let auth_mgmt = auth_mgmt.lock()?;
    
    Ok(auth_mgmt.get_keys().into_iter()
        .cloned()
        .collect())
}

#[get("/get_users")]
fn get_users(auth_mgmt: State<MAuthMgmt>) -> Json<RespStatusWithData<Vec<String>>> {
    into_json_resp_status_with_data(get_users_impl(auth_mgmt))
}

#[get("/get_default_creds")]
fn get_default_creds() -> Json<RespStatusWithData<UserPwCreds>> {
    Json(RespStatusWithData::ok(UserPwCreds::default()))
}

fn action_to_msg(query: Option<&str>) -> Option<&'static str> {
    query.and_then(|action| {
        match action {
            "password" => Some("Successfully changed password!"),
            "add" => Some("Successfully added new user!"),
            "update" => Some("Successfully updated user!"),
            "delete" => Some("Successfully deleted user(s)!"),
            _ => None,
        }
    })
}

#[get("/overview")]
fn overview(uri: &URI, mappings: State<MMappings>, config: State<MainConfig>, cookies: Cookies) -> Result<Template, Redirect> {
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

    let prev_action_msg = action_to_msg(uri.query());
    let has_prev_action = prev_action_msg.is_some();

    let auth_bin_path_canon = match Path::new(&config.auth_bin_path).canonicalize() {
        Ok(auth_bin_path_canon) => auth_bin_path_canon,
        Err(_) => Path::new(&config.auth_bin_path).to_owned(),
    };

    let context = OverviewTemplateContext::new(
        username.to_owned(),
        auth_bin_path_canon,
        has_prev_action,
        prev_action_msg.map(|msg| msg.to_owned()));

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
    #[structopt(long = "address", help = "Interface address to host", default_value = "0.0.0.0")]
    address: String,

    #[structopt(short = "p", long = "port", help = "Port to host", default_value = "9090")]
    port: u16,

    #[structopt(long = "priv", help = "Private key file path", default_value = "ssl/key.pem")]
    key_path: String,

    #[structopt(long = "pub", help = "Certificate file path", default_value = "ssl/cert.pem")]
    cert_path: String,

    #[structopt(long = "auth", help = "Authentication BIN file path")]
    auth_bin_path: String,

    #[structopt(short = "l", long = "log", help = "Log config file path")]
    log_config_path: Option<String>,
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

            let add_res = auth_mgmt.add(
                "admin".to_owned(), "admin".to_owned(),
                &AdminTaskCredentials {
                    allowed_roles: AllowedRoles {
                        add_users: Some(true),
                        update_users: Some(true),
                        delete_users: Some(true),
                        ..Default::default()
                    },
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
        .tls(config.cert_path.clone(), config.key_path.clone())
        .finalize()
        .chain_err(|| "Unable to create the custom rocket configuration!")?;

    rocket::custom(rocket_config, false)
        .manage(config)
        .manage(Mutex::new(auth_mgmt))
        .manage(Mutex::new((UserMappings::new(), TokenMappings::new())))
        .attach(Template::fairing())
        .mount("/", routes![
            index, overview, get_images, get_js, get_css,
            login, get_users, get_default_creds, exchange, info, change_password,
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
