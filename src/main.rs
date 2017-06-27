#[macro_use]
extern crate error_chain;

#[macro_use]
extern crate log;
extern crate log4rs;
extern crate serde;

#[macro_use]
extern crate serde_derive;
extern crate simple_logger;
extern crate structopt;

#[macro_use]
extern crate structopt_derive;

use std::process;
use structopt::StructOpt;

#[derive(Debug, PartialEq, Deserialize, Serialize)]
struct Credentials {
    username: String,
    password: String,
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct CommonRoleFlags {
    start: bool,
    stop: bool,
    shutdown: bool,
    erase: bool,
    config_read: bool,
    config_update: bool,
    initiated_bit: bool,
    continuous_bit: bool,
    explore: bool,
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct OxxxOnlyRoleFlags {
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
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct OxxxRoleFlags {
    common_role_flags: CommonRoleFlags,
    oxxx_only_role_flags: OxxxOnlyRoleFlags,
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct OxxxAdminTaskCredentials {
    admin_credentials: Option<Credentials>,
    sensor_id: String,
    allowed_roles: OxxxRoleFlags,
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct VxxOnlyRoleFlags {
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
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct VxxRoleFlags {
    common_role_flags: CommonRoleFlags,
    vxx_only_role_flags: VxxOnlyRoleFlags,
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct E2RoleFlags {
    common_role_flags: CommonRoleFlags,
    vxx_only_role_flags: VxxOnlyRoleFlags,
    oxxx_only_role_flags: OxxxOnlyRoleFlags,
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct E2AdminTaskCredentials {
    admin_credentials: Option<Credentials>,
    sensor_id: String,
    fx_credentials: Credentials,
    allow_roles: E2RoleFlags,
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ImbuedPayload<T> {
    t: T,
    get_users: Option<bool>,
    add_users: Option<bool>,
    update_users: Option<bool>,
    delete_users: Option<bool>,
}

mod errors {
    error_chain! {
        errors {}
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

//     let fbuf = FileBuffer::open(&config.auth_bin_path)
//         .chain_err(|| format!("Unable to open '{}'", config.auth_bin_path))?;

//     let mut de = Deserializer::new(&fbuf[..]);

//     let auth_mgmt: AuthMgmt = Deserialize::deserialize(&mut de)
//         .chain_err(|| format!("Unable to deserialize content from '{}' into AuthMgmt", config.auth_bin_path))?;

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