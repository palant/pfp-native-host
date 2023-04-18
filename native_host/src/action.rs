use serde::{Deserialize, Deserializer};

#[derive(Debug)]
pub(crate) struct Action {
    pub request_id: String,
    pub request: Request,
}

impl<'de> Deserialize<'de> for Action {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct MapVisitor;
        impl<'de> serde::de::Visitor<'de> for MapVisitor {
            type Value = Action;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "action structure")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                use serde::de::Error;

                let mut request_id = None;
                let mut action = None;
                let mut request = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        "request_id" => {
                            if request_id.is_some() {
                                return Err(A::Error::duplicate_field("request_id"));
                            }
                            request_id = Some(map.next_value()?);
                        }
                        "action" => {
                            if action.is_some() {
                                return Err(A::Error::duplicate_field("action"));
                            }
                            action = Some(map.next_value::<String>()?);
                        }
                        "request" => {
                            if request.is_some() {
                                return Err(A::Error::duplicate_field("request"));
                            }
                            request = Some(map.next_value::<serde_json::Value>()?);
                        }
                        other => {
                            return Err(A::Error::unknown_field(
                                other,
                                &["request_id", "action", "request"],
                            ))
                        }
                    }
                }

                // Produce the expected JSON structure in order to deserialize the enum
                let json = serde_json::json!({
                    action.ok_or(A::Error::missing_field("action"))?:
                        request.ok_or(A::Error::missing_field("request"))?
                });
                let request_vec = serde_json::to_vec(&json).map_err(|e| A::Error::custom(e))?;

                Ok(Self::Value {
                    request_id: request_id.ok_or(A::Error::missing_field("request_id"))?,
                    request: serde_json::from_slice(&request_vec)
                        .map_err(|e| A::Error::custom(e))?,
                })
            }
        }

        deserializer.deserialize_map(MapVisitor)
    }
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
