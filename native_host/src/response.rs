use serde::Serialize;

use keepass_db::Entry;

#[derive(Serialize, Debug)]
pub(crate) struct ActionResponse {
    pub request_id: String,
    pub success: bool,
    pub response: Response,
}

#[derive(Serialize, Debug)]
#[serde(untagged)]
pub(crate) enum Response {
    Error(ErrorResponse),
    Keys(Vec<String>),
    SiteEntries(SiteEntriesResponse),
    AllEntries(AllEntriesResponse),
    Sites(Vec<String>),
    String(String),
    DerivedKey(DeriveKeyResponse),
    None,
}

#[derive(Serialize, Debug)]
pub(crate) struct ErrorResponse {
    pub error: String,
    pub error_code: &'static str,
}

#[derive(Serialize, Debug)]
pub(crate) struct SiteEntriesResponse {
    pub hostname: String,
    pub entries: Vec<Entry>,
}

#[derive(Serialize, Debug)]
pub(crate) struct AllEntriesResponse {
    pub aliases: std::collections::HashMap<String, String>,
    pub entries: Vec<Entry>,
}

#[derive(Serialize, Debug)]
pub(crate) struct DeriveKeyResponse {
    pub key: String,
    pub bytes_consumed: u32,
}
