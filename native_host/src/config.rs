use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

use crate::error::Error;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Config {
    pub databases: HashMap<String, PathBuf>,
    pub default_database: String,
}

impl Config {
    fn config_path() -> Result<PathBuf, Error> {
        let mut path = std::env::current_exe().or(Err(Error::UnknownConfigLocation))?;
        path.pop();
        path.push("pfp-native-host-config.json");
        Ok(path)
    }

    pub fn read() -> Option<Self> {
        let config_path = Self::config_path().ok()?;
        let reader = std::fs::File::open(config_path).ok()?;
        serde_json::from_reader(reader).ok()
    }

    pub fn save(&self) -> Result<(), Error> {
        let config_path = Self::config_path()?;
        let writer = std::fs::File::create(config_path)?;
        serde_json::to_writer_pretty(writer, self)?;
        Ok(())
    }
}
