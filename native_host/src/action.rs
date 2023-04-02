use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub(crate) struct Action {
    pub request_id: String,
    #[serde(flatten)]
    pub request: Request,
}

#[derive(Deserialize, Debug)]
pub(crate) enum Request {
    #[serde(rename = "unlock")]
    Unlock(UnlockParameters),
    #[serde(rename = "get-entries")]
    GetEntries(GetEntriesParameters),
    #[serde(rename = "get-all-entries")]
    GetAllEntries(GetAllEntriesParameters),
    #[serde(rename = "get-sites")]
    GetSites(GetSitesParameters),
    #[serde(rename = "add-entry")]
    AddEntry(AddEntryParameters),
    #[serde(rename = "update-entry")]
    UpdateEntry(UpdateEntryParameters),
    #[serde(rename = "duplicate-entry")]
    DuplicateEntry(DuplicateEntryParameters),
    #[serde(rename = "remove-entry")]
    RemoveEntry(RemoveEntryParameters),
    #[serde(rename = "duplicate-kdf-parameters")]
    DuplicateKDFParameters,
    #[serde(rename = "derive-key")]
    DeriveKey(DeriveKeyParameters),
    #[serde(rename = "add-alias")]
    AddAlias(AddAliasParameters),
    #[serde(rename = "remove-alias")]
    RemoveAlias(RemoveAliasParameters),
    #[serde(rename = "set-aliases")]
    SetAliases(SetAliasesParameters),
}

#[derive(Deserialize, Debug)]
pub(crate) struct UnlockParameters {
    pub password: String,
}

#[derive(Deserialize, Debug)]
pub(crate) struct GetEntriesParameters {
    pub keys: Vec<String>,
    pub hostname: String,
}

#[derive(Deserialize, Debug)]
pub(crate) struct GetAllEntriesParameters {
    pub keys: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub(crate) struct GetSitesParameters {
    pub keys: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub(crate) struct AddEntryParameters {
    pub keys: Vec<String>,
    pub hostname: String,
    pub title: String,
    pub username: String,
    pub password: String,
}

#[derive(Deserialize, Debug)]
pub(crate) struct UpdateEntryParameters {
    pub keys: Vec<String>,
    pub uuid: String,
    pub hostname: Option<String>,
    pub title: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub notes: Option<String>,
}

#[derive(Deserialize, Debug)]
pub(crate) struct DuplicateEntryParameters {
    pub keys: Vec<String>,
    pub uuid: String,
}

#[derive(Deserialize, Debug)]
pub(crate) struct RemoveEntryParameters {
    pub keys: Vec<String>,
    pub uuid: String,
}

#[derive(Deserialize, Debug)]
pub(crate) struct DeriveKeyParameters {
    pub password: String,
    pub kdf_parameters: String,
}

#[derive(Deserialize, Debug)]
pub(crate) struct AddAliasParameters {
    pub keys: Vec<String>,
    pub alias: String,
    pub hostname: String,
}

#[derive(Deserialize, Debug)]
pub(crate) struct RemoveAliasParameters {
    pub keys: Vec<String>,
    pub alias: String,
}

#[derive(Deserialize, Debug)]
pub(crate) struct SetAliasesParameters {
    pub keys: Vec<String>,
    pub aliases: std::collections::HashMap<String, String>,
}
