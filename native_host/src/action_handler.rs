use base64::Engine;
use keepass_db::io::{Deserialize, Serialize};
use keepass_db::{Database, DatabaseXML, Entry, KdfParameters, Keys};
use std::collections::HashSet;

use crate::action::{Action, Request};
use crate::config::Config;
use crate::error::Error;
use crate::response::{AllEntriesResponse, DeriveKeyResponse, Response, SiteEntriesResponse};

fn get_input() -> Result<impl std::io::Read, Error> {
    let path = Config::get_database_path().ok_or(Error::Unconfigured)?;
    let file = std::fs::File::open(path)?;
    Ok(std::io::BufReader::new(file))
}

fn get_keys(mut array: Vec<String>) -> Result<Keys, Error> {
    let hmac = array.pop().ok_or(Error::InvalidMessage)?;
    let encryption = array.pop().ok_or(Error::InvalidMessage)?;
    if array.is_empty() {
        let keys = Keys::from_string(encryption, hmac)?;
        Ok(keys)
    } else {
        Err(Error::InvalidMessage)
    }
}

fn get_title_base(title: &str) -> (String, u32) {
    if let Some((base_name, index)) = title.rsplit_once(" #") {
        if let Ok(index) = index.parse::<u32>() {
            return (base_name.to_string(), index);
        }
    }
    (title.to_string(), 1)
}

fn get_database_xml(keys: Vec<String>) -> Result<(Database, DatabaseXML, Keys), Error> {
    let keys = get_keys(keys)?;
    let mut input = get_input()?;
    let database = Database::deserialize(&mut input)?;
    let database_xml = database.decrypt(&mut input, &keys)?;
    Ok((database, database_xml, keys))
}

fn save_database(
    database: &mut Database,
    database_xml: &mut DatabaseXML,
    keys: &Keys,
) -> Result<(), Error> {
    let path = Config::get_database_path().ok_or(Error::Unconfigured)?;
    let file = std::fs::File::create(path)?;
    let mut writer = std::io::BufWriter::new(file);
    database.save(&mut writer, keys, database_xml)?;
    Ok(())
}

pub(crate) fn handle(action: Action) -> Result<Response, Error> {
    match action.request {
        Request::GetProtocol => {
            Ok(Response::String("1.0".to_string()))
        }
        Request::Unlock(params) => {
            let mut input = get_input()?;
            let database = Database::deserialize(&mut input)?;
            let keys = database.unlock(&params.password)?;
            let (encryption, hmac) = keys.to_string();
            Ok(Response::Keys([encryption, hmac].to_vec()))
        }
        Request::GetEntries(params) => {
            let (_, database_xml, _) = get_database_xml(params.keys)?;
            let aliases = database_xml.get_aliases();
            let hostname = aliases.get(&params.hostname).unwrap_or(&params.hostname);
            Ok(Response::SiteEntries(SiteEntriesResponse {
                hostname: hostname.to_string(),
                entries: database_xml
                    .get_entries()
                    .filter(|entry| entry.hostname().eq_ignore_ascii_case(hostname))
                    .collect::<Vec<_>>(),
            }))
        }
        Request::GetAllEntries(params) => {
            let (_, database_xml, _) = get_database_xml(params.keys)?;
            Ok(Response::AllEntries(AllEntriesResponse {
                aliases: database_xml.get_aliases(),
                entries: database_xml.get_entries().collect::<Vec<_>>(),
            }))
        }
        Request::GetSites(params) => {
            let (_, database_xml, _) = get_database_xml(params.keys)?;
            Ok(Response::Sites(
                database_xml
                    .get_entries()
                    .map(|entry| entry.hostname())
                    .collect::<HashSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>(),
            ))
        }
        Request::AddEntry(params) => {
            let (mut database, mut database_xml, keys) = get_database_xml(params.keys)?;

            if database_xml.get_entries().any(|entry| {
                entry.hostname().eq_ignore_ascii_case(&params.hostname)
                    && entry.title.eq_ignore_ascii_case(&params.title)
            }) {
                return Err(Error::EntryExists);
            }

            let mut entry = Entry::new("", &params.title, &params.username, &params.password)?;
            entry.set_hostname(params.hostname);
            let protected = database_xml.get_protected_fields();
            let uuid = database_xml.add_entry(entry, &protected)?;

            save_database(&mut database, &mut database_xml, &keys)?;
            Ok(Response::String(uuid))
        }
        Request::UpdateEntry(params) => {
            let (mut database, mut database_xml, keys) = get_database_xml(params.keys)?;
            let mut entry = database_xml.get_entry(&params.uuid)?;
            if let Some(hostname) = params.hostname {
                entry.set_hostname(hostname);
            }
            if let Some(title) = params.title {
                entry.title = title;
            }
            if let Some(username) = params.username {
                entry.username = username;
            }
            if let Some(password) = params.password {
                entry.password = password;
            }
            if let Some(notes) = params.notes {
                entry.notes = if notes.is_empty() { None } else { Some(notes) };
            }

            if database_xml.get_entries().any(|e| {
                e.hostname().eq_ignore_ascii_case(&entry.hostname())
                    && e.title.eq_ignore_ascii_case(&entry.title)
                    && e.uuid != entry.uuid
            }) {
                return Err(Error::EntryExists);
            }

            let protected = database_xml.get_protected_fields();
            database_xml.update_entry(entry, &protected)?;
            save_database(&mut database, &mut database_xml, &keys)?;
            Ok(Response::None)
        }
        Request::DuplicateEntry(params) => {
            let (mut database, mut database_xml, keys) = get_database_xml(params.keys)?;
            let mut entry = database_xml.get_entry(&params.uuid)?;

            let hostname = entry.hostname();
            let existing_titles = database_xml
                .get_entries()
                .filter(|entry| entry.hostname() == hostname)
                .map(|entry| entry.title)
                .collect::<HashSet<_>>();

            entry.uuid = Entry::generate_uuid()?;
            let (base_name, mut index) = get_title_base(&entry.title);
            index += 1;
            loop {
                let title = format!("{base_name} #{index}");
                if !existing_titles.contains(&title) {
                    entry.title = title;
                    break;
                }
                index += 1;
            }
            let protected = database_xml.get_protected_fields();
            let uuid = database_xml.add_entry(entry, &protected)?;

            save_database(&mut database, &mut database_xml, &keys)?;
            Ok(Response::String(uuid))
        }
        Request::RemoveEntry(params) => {
            let (mut database, mut database_xml, keys) = get_database_xml(params.keys)?;
            database_xml.remove_entry(&params.uuid)?;

            save_database(&mut database, &mut database_xml, &keys)?;
            Ok(Response::None)
        }
        Request::DuplicateKdfParameters => {
            let mut input = get_input()?;
            let database = Database::deserialize(&mut input)?;
            let mut parameters = database.get_kdf_parameters().clone();
            parameters.reset_salt()?;

            let mut buffer = Vec::new();
            parameters.serialize(&mut buffer)?;

            let result = base64::engine::general_purpose::STANDARD.encode(buffer);
            Ok(Response::String(result))
        }
        Request::DeriveKey(params) => {
            const KEY_SIZE: usize = 32;

            let mut buffer = base64::engine::general_purpose::STANDARD
                .decode(params.kdf_parameters)
                .or(Err(Error::InvalidMessage))?;
            let mut cursor = std::io::Cursor::new(&mut buffer);
            let parameters = KdfParameters::deserialize(&mut cursor)?;

            let key = parameters.derive_key(params.password.as_bytes(), KEY_SIZE)?;
            Ok(Response::DerivedKey(DeriveKeyResponse {
                key: base64::engine::general_purpose::STANDARD.encode(key),
                bytes_consumed: cursor.position() as u32,
            }))
        }
        Request::AddAlias(params) => {
            let (mut database, mut database_xml, keys) = get_database_xml(params.keys)?;
            database_xml.add_alias(&params.alias, &params.hostname);

            save_database(&mut database, &mut database_xml, &keys)?;
            Ok(Response::None)
        }
        Request::RemoveAlias(params) => {
            let (mut database, mut database_xml, keys) = get_database_xml(params.keys)?;
            database_xml.remove_alias(&params.alias);

            save_database(&mut database, &mut database_xml, &keys)?;
            Ok(Response::None)
        }
        Request::SetAliases(params) => {
            let (mut database, mut database_xml, keys) = get_database_xml(params.keys)?;
            database_xml.set_aliases(params.aliases);

            save_database(&mut database, &mut database_xml, &keys)?;
            Ok(Response::None)
        }
    }
}
