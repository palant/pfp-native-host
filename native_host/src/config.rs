use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::error::Error;

const APP_INFO: app_dirs2::AppInfo = app_dirs2::AppInfo {
    name: "pfp-native-host",
    author: "Wladimir Palant",
};

#[derive(Serialize, Deserialize)]
pub(crate) struct Config {
    database: PathBuf,
}

impl Config {
    fn config_path() -> Result<PathBuf, Error> {
        let mut path = app_dirs2::app_root(app_dirs2::AppDataType::UserConfig, &APP_INFO)?;
        path.push("config.json");
        Ok(path)
    }

    pub fn get_database_path() -> Option<PathBuf> {
        let config_path = Self::config_path().ok()?;
        let reader = std::fs::File::open(config_path).ok()?;
        let config: Self = serde_json::from_reader(reader).ok()?;
        Some(config.database)
    }

    pub fn set_database_path(path: PathBuf) -> Result<(), Error> {
        let config_path = Self::config_path()?;
        let writer = std::fs::File::create(config_path)?;
        serde_json::to_writer_pretty(
            writer,
            &Self {
                database: path.canonicalize().unwrap_or(path),
            },
        )?;
        Ok(())
    }
}
