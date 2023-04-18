#![feature(trace_macros)]

mod action;
mod action_handler;
mod browser_support;
mod config;
mod error;
mod native_host;
mod response;

use dialoguer::{Input, Select};
use keepass_db::io::Deserialize;
use keepass_db::Database;
use std::path::PathBuf;

use config::Config;
use error::Error;

fn database_valid(path: &PathBuf) -> Result<(), Error> {
    let mut file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(&mut file);
    Database::deserialize(&mut reader)?;
    Ok(())
}

fn try_database(path: &PathBuf) -> bool {
    match database_valid(path) {
        Ok(()) => true,
        Err(error) => {
            eprintln!(
                "Database file {} could not be opened: {error}.",
                path.display()
            );
            false
        }
    }
}

fn select_database() -> Result<(), Error> {
    let items = &["Select an existing database", "Create a new database"];
    let selection = Select::new()
        .with_prompt("Please choose an action to configure kdbx-native-host")
        .items(items)
        .default(0)
        .interact_opt()?
        .ok_or(Error::Aborted)?;
    if selection == 0 {
        match native_dialog::FileDialog::new()
            .add_filter("KeePass database", &["kdbx"])
            .show_open_single_file()
        {
            Ok(Some(path)) => Config::set_database_path(path),
            Ok(None) => Err(Error::Aborted),
            Err(native_dialog::Error::NoImplementation) => {
                let input: String = Input::new()
                    .with_prompt("Please enter the database path")
                    .interact_text()?;
                Config::set_database_path(PathBuf::from(input))
            }
            Err(error) => Err(error.into()),
        }
    } else {
        Ok(())
    }
}

fn setup_database() -> Result<(), Error> {
    match Config::get_database_path() {
        Some(path) => {
            eprintln!("Currently configured database file is {}.", path.display());
            let selection = Select::new()
                .with_prompt("Keep this database file")
                .items(&["Yes", "No"])
                .default(0)
                .interact_opt()?
                .ok_or(Error::Aborted)?;

            if selection != 0 || !try_database(&path) {
                select_database()?;
                return setup_database();
            }
            setup_browsers()
        }
        None => {
            eprintln!("Database is not configured.");
            select_database()?;
            setup_database()
        }
    }
}

fn setup_browsers() -> Result<(), Error> {
    loop {
        let configured = browser_support::Browser::all()
            .iter()
            .filter(|b| b.is_configured())
            .map(|b| b.name())
            .collect::<Vec<_>>();
        if configured.is_empty() {
            eprintln!("No browsers are currently configured.");
        } else {
            eprintln!("Currently configured browsers: {}", configured.join(", "));
        }

        let items = browser_support::Browser::all()
            .iter()
            .map(|b| b.name())
            .collect::<Vec<_>>();
        let selection = Select::new()
            .with_prompt("Please choose a browser to configure or press Esc to exit")
            .items(&items)
            .default(0)
            .interact_opt()?
            .ok_or(Error::Aborted)?;

        let browser = &browser_support::Browser::all()[selection];
        let extension_id = Input::new()
            .with_prompt("Please enter an extension ID or press Enter to keep the default")
            .default(browser.extension_id().to_string())
            .interact_text()?;
        browser.configure(&extension_id)?;
    }
}

fn main_inner() -> Result<(), Error> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 2 && args[1].contains("://") {
        native_host::run_server()
    } else {
        setup_database()
    }
}

fn main() -> std::process::ExitCode {
    if let Err(error) = main_inner() {
        if !matches!(error, Error::Aborted) {
            eprintln!("{}", error);
        }
        std::process::ExitCode::FAILURE
    } else {
        std::process::ExitCode::SUCCESS
    }
}
