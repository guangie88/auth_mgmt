use auth_mgmt::{self, AuthMgmt};
use bidir_map::BidirMap;
use serde::{self, Deserialize, Serialize};
use std;
use std::collections::HashMap;
use std::sync::Mutex;

// constants
pub const TOKEN_NAME: &'static str = "token";

pub const RESP_OK: &'static str = "ok";
pub const RESP_INVALID_TOKEN: &'static str = "invalid token";
pub const RESP_NO_SUCH_COOKIE: &'static str = "no such cookie";
pub const RESP_NO_SUCH_CREDENTIALS: &'static str = "no such credentials";
pub const RESP_NOT_ALLOWED: &'static str = "not allowed";
pub const RESP_UNABLE_TO_CONVERT_TO_MSGPACK: &'static str = "unable to convert to msgpack";
pub const RESP_UNABLE_TO_LOCK: &'static str = "unable to lock";
pub const RESP_UNABLE_TO_PROCESS: &'static str = "unable to process";
pub const RESP_UNABLE_TO_WRITE_FILE: &'static str = "unable to write file";

pub const WEB_INDEX_PATH: &'static str = "/";
pub const WEB_OVERVIEW_PATH: &'static str = "/overview";

#[derive(new, Debug, PartialEq, Deserialize, Serialize)]
pub struct RespStatus {
    pub status: String,
}

#[derive(new, Debug, PartialEq, Deserialize, Serialize)]
#[serde(bound(deserialize = ""))]
pub struct RespStatusWithData<T>
where T: for<'de_inner> Deserialize<'de_inner> + Serialize {
    pub status: String,
    pub data: Option<T>,
}

#[derive(Default, Debug, Clone, FromForm, PartialEq, Deserialize, Serialize)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

#[derive(new, Debug, Serialize)]
pub struct IndexTemplateContext {
    pub fail: bool,
}

#[derive(new, Debug, Serialize)]
pub struct OverviewTemplateContext {
    pub username: String,
}

#[derive(Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct UserPwCreds {
    pub username: String,
    pub password: String,
    pub creds: AdminTaskCredentials,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OxxxAdminTaskCredentials {
    #[serde(skip_serializing_if="Option::is_none")]
    pub admin_credentials: Option<Credentials>,
    pub sensor_id: String,

    // CommonRoleFlags
    pub start: bool,
    pub stop: bool,
    pub shutdown: bool,
    pub erase: bool,
    pub config_read: bool,
    pub config_update: bool,
    pub initiated_bit: bool,
    pub continuous_bit: bool,
    pub explore: bool,
    
    // OxxxOnlyRoleFlags
    pub verify_oxxx_nxxs: bool,
    pub import_oxxx_nxxs: bool,
    pub export_oxxx_nxxs: bool,
    pub oxxx_nxxs_read: bool,
    pub oxxx_nxxs_schema_read: bool,
    pub oxxx_nxxs_update: bool,
    pub oxxx_nxxs_delete: bool,
    pub oxxx_tasks_read: bool,
    pub oxxx_tasks_schema_read: bool,
    pub oxxx_ref_lxx_read: bool,
    pub oxxx_ref_lxx_update: bool,

    // ImbuedPayload
    #[serde(skip_serializing_if="Option::is_none")]
    pub get_users: Option<bool>,

    #[serde(skip_serializing_if="Option::is_none")]
    pub add_users: Option<bool>,

    #[serde(skip_serializing_if="Option::is_none")]
    pub update_users: Option<bool>,
    
    #[serde(skip_serializing_if="Option::is_none")]
    pub delete_users: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct E2AdminTaskCredentials {
    #[serde(skip_serializing_if="Option::is_none")]
    pub admin_credentials: Option<Credentials>,
    pub sensor_id: String,
    pub fx_credentials: Credentials,

    // CommonRoleFlags
    pub start: bool,
    pub stop: bool,
    pub shutdown: bool,
    pub erase: bool,
    pub config_read: bool,
    pub config_update: bool,
    pub initiated_bit: bool,
    pub continuous_bit: bool,
    pub explore: bool,

    // VxxOnlyRoleFlags
    pub verify_vxx_nxxs: bool,
    pub import_vxx_nxxs: bool,
    pub export_vxx_nxxs: bool,
    pub send_to_merge_nxx: bool,
    pub send_to_rename_nxx: bool,
    pub send_to_prioritize_nxx: bool,
    pub vxx_nxxs_read: bool,
    pub vxx_nxxs_update: bool,
    pub vxx_nxxs_delete: bool,
    pub vxx_tasks_read: bool,
    pub recv_production_result: bool,
    pub send_bxxxx_fxxxs: bool,
    pub send_vvv_production_resubmit_request: bool,
    pub send_ww_stxxxing_production_request: bool,
    
    // OxxxOnlyRoleFlags
    pub verify_oxxx_nxxs: bool,
    pub import_oxxx_nxxs: bool,
    pub export_oxxx_nxxs: bool,
    pub oxxx_nxxs_read: bool,
    pub oxxx_nxxs_schema_read: bool,
    pub oxxx_nxxs_update: bool,
    pub oxxx_nxxs_delete: bool,
    pub oxxx_tasks_read: bool,
    pub oxxx_tasks_schema_read: bool,
    pub oxxx_ref_lxx_read: bool,
    pub oxxx_ref_lxx_update: bool,

    // ImbuedPayload
    #[serde(skip_serializing_if="Option::is_none")]
    pub get_users: Option<bool>,

    #[serde(skip_serializing_if="Option::is_none")]
    pub add_users: Option<bool>,

    #[serde(skip_serializing_if="Option::is_none")]
    pub update_users: Option<bool>,

    #[serde(skip_serializing_if="Option::is_none")]
    pub delete_users: Option<bool>,
}

impl<T> From<RespStatus> for RespStatusWithData<T>
where T: for<'de_inner> serde::Deserialize<'de_inner> + Serialize {
    fn from(e: RespStatus) -> RespStatusWithData<T> {
        RespStatusWithData::new(e.status, None)
    }
}

impl RespStatus {
    pub fn ok() -> RespStatus {
        RespStatus { status: RESP_OK.to_owned(), }
    }
}

impl<T> RespStatusWithData<T>
where T: for<'de_inner> Deserialize<'de_inner> + Serialize {
    pub fn ok(v: T) -> RespStatusWithData<T> {
        RespStatusWithData {
            status: RESP_OK.to_owned(),
            data: Some(v),
        }
    }
}

impl Default for OxxxAdminTaskCredentials {
    fn default() -> Self {
        OxxxAdminTaskCredentials {
            admin_credentials: Some(Credentials::default()),
            sensor_id: String::new(),

            start: false,
            stop: false,
            shutdown: false,
            erase: false,
            config_read: false,
            config_update: false,
            initiated_bit: false,
            continuous_bit: true,
            explore: true,

            verify_oxxx_nxxs: true,
            import_oxxx_nxxs: true,
            export_oxxx_nxxs: true,
            oxxx_nxxs_read: true,
            oxxx_nxxs_schema_read: true,
            oxxx_nxxs_update: true,
            oxxx_nxxs_delete: true,
            oxxx_tasks_read: true,
            oxxx_tasks_schema_read: true,
            oxxx_ref_lxx_read: true,
            oxxx_ref_lxx_update: true,

            get_users: Some(false),
            add_users: Some(false),
            update_users: Some(false),
            delete_users: Some(false),
        }
    }
}

impl Default for E2AdminTaskCredentials {
    fn default() -> Self {
        E2AdminTaskCredentials {
            admin_credentials: Some(Credentials::default()),
            sensor_id: String::new(),
            fx_credentials: Credentials::default(),

            start: true,
            stop: true,
            shutdown: true,
            erase: true,
            config_read: true,
            config_update: true,
            initiated_bit: true,
            continuous_bit: true,
            explore: true,

            verify_vxx_nxxs: true,
            import_vxx_nxxs: true,
            export_vxx_nxxs: true,
            send_to_merge_nxx: true,
            send_to_rename_nxx: true,
            send_to_prioritize_nxx: true,
            vxx_nxxs_read: true,
            vxx_nxxs_update: true,
            vxx_nxxs_delete: true,
            vxx_tasks_read: true,
            recv_production_result: true,
            send_bxxxx_fxxxs: true,
            send_vvv_production_resubmit_request: true,
            send_ww_stxxxing_production_request: true,

            verify_oxxx_nxxs: true,
            import_oxxx_nxxs: true,
            export_oxxx_nxxs: true,
            oxxx_nxxs_read: true,
            oxxx_nxxs_schema_read: true,
            oxxx_nxxs_update: true,
            oxxx_nxxs_delete: true,
            oxxx_tasks_read: true,
            oxxx_tasks_schema_read: true,
            oxxx_ref_lxx_read: true,
            oxxx_ref_lxx_update: true,

            get_users: Some(false),
            add_users: Some(false),
            update_users: Some(false),
            delete_users: Some(false),
        }
    }
}

pub mod errors {
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

impl From<auth_mgmt::AuthErr> for errors::Error {
    fn from(e: auth_mgmt::AuthErr) -> Self {
        Self::from_kind(errors::ErrorKind::AuthErr(format!("{:?}", e)))
    }
}

impl<T> From<std::sync::PoisonError<T>> for errors::Error {
    fn from(e: std::sync::PoisonError<T>) -> Self {
        use std::error::Error;
        Self::from_kind(errors::ErrorKind::SyncPoisonError(e.description().to_string()))
    }
}



// change between OxxxAdminTaskCredentials and E2AdminTaskCredentials
pub type User = String;
pub type Token = String;
pub type AdminTaskCredentials = E2AdminTaskCredentials;
pub type UserMappings = BidirMap<User, Token>;
pub type TokenMappings = HashMap<Token, AdminTaskCredentials>;
pub type MAuthMgmt = Mutex<AuthMgmt>;
pub type MMappings = Mutex<(UserMappings, TokenMappings)>;