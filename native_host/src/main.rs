#![feature(trace_macros)]

mod action;
mod action_handler;
mod browser_support;
mod config;
mod error;
mod native_host;
mod response;

use dialoguer::{Input, Password, Select};
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

fn choose_path(save: bool) -> Result<PathBuf, Error> {
    let dialog = native_dialog::FileDialog::new().add_filter("KeePass database", &["kdbx"]);
    let result = if save {
        dialog.show_save_single_file()
    } else {
        dialog.show_open_single_file()
    };

    match result {
        Ok(Some(path)) => Ok(path),
        Ok(None) => Err(Error::Aborted),
        Err(native_dialog::Error::NoImplementation) => {
            let input: String = Input::new()
                .with_prompt("Please enter the database path")
                .interact_text()?;
            Ok(PathBuf::from(input))
        }
        Err(error) => Err(error.into()),
    }
}

fn create_database(path: &PathBuf) -> Result<(), Error> {
    let mut memory = 1024;
    let mut parallelism = num_cpus::get() as u32;
    let mut seconds = 1.0;
    let selection = Select::new()
        .with_prompt(format!("Use default key derivation parameters ({memory} MiB, {parallelism} threads, {seconds} seconds to unlock)"))
        .items(&["Yes", "No"])
        .default(0)
        .interact_opt()?
        .ok_or(Error::Aborted)?;
    if selection != 0 {
        memory = Input::new()
            .with_prompt(
                "Enter the amount of memory in MiB to be used for key derivation (more is better)",
            )
            .default(memory)
            .interact_text()?
            .max(1);
        parallelism = Input::new()
            .with_prompt(
                "Enter the number of parallel threads (ideally the number of your CPU cores)",
            )
            .default(parallelism)
            .interact_text()?
            .max(1);
        seconds = Input::new()
            .with_prompt("Enter the time in seconds spent unlocking the database (more is better)")
            .default(seconds)
            .validate_with(|input: &f32| {
                if *input >= 0.1 && *input <= 10.0 {
                    Ok(())
                } else {
                    Err("Please enter a number between 0.1 and 10")
                }
            })
            .interact_text()?;
    }
    let kdf_parameters = keepass_db::KdfParameters::generate(memory * 1024, parallelism, seconds)?;

    let main_password = Password::new()
        .with_prompt("Main password for the database")
        .with_confirmation("Confirm password", "Passwords don't match")
        .interact()?;

    let file = std::fs::File::create(path)?;
    let mut writer = std::io::BufWriter::new(file);
    keepass_db::Database::save_new(&mut writer, &main_password, kdf_parameters)?;
    Ok(())
}

fn select_database() -> Result<(), Error> {
    let items = &["Select an existing database", "Create a new database"];
    let selection = Select::new()
        .with_prompt("If you already have a KeePass database, this application can use it")
        .items(items)
        .default(0)
        .interact_opt()?
        .ok_or(Error::Aborted)?;
    if selection == 0 {
        Config::set_database_path(choose_path(false)?)
    } else {
        let path = choose_path(true)?;
        create_database(&path)?;
        Config::set_database_path(path)
    }
}

fn setup_database() -> Result<(), Error> {
    match Config::get_database_path() {
        Some(path) => {
            eprintln!("Currently configured database file is {}.", path.display());
            let selection = Select::new()
                .with_prompt("Keep using this database file")
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
