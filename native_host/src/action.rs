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

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(formatter, "action structure")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                use serde::de::Error;
                use serde::de::IntoDeserializer;

                const REQUEST_ID_FIELD: &str = "requestId";
                const ACTION_FIELD: &str = "action";
                const REQUEST_FIELD: &str = "request";

                let mut request_id = None;
                let mut action = None;
                let mut request = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        REQUEST_ID_FIELD => {
                            if request_id.is_some() {
                                return Err(A::Error::duplicate_field(REQUEST_ID_FIELD));
                            }
                            request_id = Some(map.next_value()?);
                        }
                        ACTION_FIELD => {
                            if action.is_some() {
                                return Err(A::Error::duplicate_field(ACTION_FIELD));
                            }
                            action = Some(map.next_value::<String>()?);
                        }
                        REQUEST_FIELD => {
                            if request.is_some() {
                                return Err(A::Error::duplicate_field(REQUEST_FIELD));
                            }
                            request = Some(map.next_value::<serde_json::Value>()?);
                        }
                        other => {
                            return Err(A::Error::unknown_field(
                                other,
                                &[REQUEST_ID_FIELD, ACTION_FIELD, REQUEST_FIELD],
                            ))
                        }
                    }
                }

                // Produce the expected JSON structure in order to deserialize the enum
                let json = serde_json::json!({
                    action.ok_or(A::Error::missing_field(ACTION_FIELD))?:
                        request.ok_or(A::Error::missing_field(REQUEST_FIELD))?
                });

                Ok(Self::Value {
                    request_id: request_id.ok_or(A::Error::missing_field(REQUEST_ID_FIELD))?,
                    request: Request::deserialize(json.into_deserializer())
                        .map_err(A::Error::custom)?,
                })
            }
        }

        deserializer.deserialize_map(MapVisitor)
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Request {
    GetProtocol(Option<String>),
    Unlock(UnlockParameters),
    GetEntries(GetEntriesParameters),
    GetAllEntries(GetAllEntriesParameters),
    GetSites(GetSitesParameters),
    AddEntry(AddEntryParameters),
    UpdateEntry(UpdateEntryParameters),
    DuplicateEntry(DuplicateEntryParameters),
    RemoveEntry(RemoveEntryParameters),
    DuplicateKdfParameters,
    DeriveKey(DeriveKeyParameters),
    AddAlias(AddAliasParameters),
    RemoveAlias(RemoveAliasParameters),
    SetAliases(SetAliasesParameters),
    Import(ImportParameters),
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UnlockParameters {
    pub password: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GetEntriesParameters {
    pub keys: Vec<String>,
    pub hostname: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GetAllEntriesParameters {
    pub keys: Vec<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GetSitesParameters {
    pub keys: Vec<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AddEntryParameters {
    pub keys: Vec<String>,
    pub hostname: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub notes: Option<String>,
    pub tags: Option<Vec<String>>,
    pub insecure_fill_in: Option<bool>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UpdateEntryParameters {
    pub keys: Vec<String>,
    pub uuid: String,
    pub hostname: Option<String>,
    pub title: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub notes: Option<String>,
    pub tags: Option<Vec<String>>,
    pub insecure_fill_in: Option<bool>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DuplicateEntryParameters {
    pub keys: Vec<String>,
    pub uuid: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RemoveEntryParameters {
    pub keys: Vec<String>,
    pub uuid: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DeriveKeyParameters {
    pub password: String,
    pub kdf_parameters: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AddAliasParameters {
    pub keys: Vec<String>,
    pub alias: String,
    pub hostname: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RemoveAliasParameters {
    pub keys: Vec<String>,
    pub alias: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SetAliasesParameters {
    pub keys: Vec<String>,
    pub aliases: std::collections::HashMap<String, String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ImportParameters {
    pub keys: Vec<String>,
    pub aliases: std::collections::HashMap<String, String>,
    pub entries: Vec<ImportEntry>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ImportEntry {
    pub hostname: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub notes: Option<String>,
}
