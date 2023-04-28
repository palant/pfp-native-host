#![deny(elided_lifetimes_in_paths)]
#![deny(explicit_outlives_requirements)]
#![deny(keyword_idents)]
#![deny(meta_variable_misuse)]
#![deny(missing_debug_implementations)]
#![deny(non_ascii_idents)]
#![warn(noop_method_call)]
#![deny(pointer_structural_match)]
#![deny(single_use_lifetimes)]
#![deny(trivial_casts)]
#![deny(trivial_numeric_casts)]
#![deny(unsafe_code)]
#![warn(unused_crate_dependencies)]
#![deny(unused_import_braces)]
#![deny(unused_lifetimes)]
#![warn(unused_macro_rules)]
#![warn(unused_tuple_struct_fields)]
#![deny(variant_size_differences)]

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

fn get_databases() -> (Vec<(String, PathBuf)>, String) {
    match Config::read() {
        Some(config) => {
            let mut vec = config.databases.into_iter().collect::<Vec<_>>();
            vec.sort_by_cached_key(|(name, _)| name.to_ascii_lowercase());
            (vec, config.default_database)
        }
        None => (Vec::new(), "".to_string()),
    }
}

fn save_databases(
    databases: Vec<(String, PathBuf)>,
    mut default_database: String,
) -> Result<(), Error> {
    if !databases.is_empty()
        && !databases
            .iter()
            .any(|(name, _)| name == &default_database)
    {
        default_database = databases[0].0.clone();
    }

    Config {
        databases: databases.into_iter().collect(),
        default_database,
    }
    .save()
}

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
        .with_prompt(format!("Use default key derivation parameters ({memory} MiB, {parallelism} threads, {seconds} second(s) to unlock)"))
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

    let main_password = {
        let selection = Select::new()
            .with_prompt(
                "It is recommended that you generate a random passphrase to protect the database",
            )
            .items(&["Generate passphrase", "Use own main password"])
            .default(0)
            .interact_opt()?
            .ok_or(Error::Aborted)?;
        if selection == 0 {
            // By including the file as a string we waste a little memory when the passphrase is generated,
            // but we save quite a bit on the binary size compared to having an array literal here.
            const WORD_LIST: &str = include_str!("eff_short_wordlist_1.txt");

            let size = Select::new()
                .with_prompt("Please choose passphrase length")
                .items(&["5 words (good)", "6 words (great)", "7 words (excellent)"])
                .default(0)
                .interact_opt()?
                .ok_or(Error::Aborted)?
                + 5;

            let words = WORD_LIST.split(',').collect::<Vec<_>>();
            let phrase = (0..size)
                .map(|_| {
                    let mut buffer = [0; usize::BITS as usize / 8];
                    getrandom::getrandom(&mut buffer)
                        .or(Err(keepass_db::Error::RandomNumberGeneratorFailed))?;
                    Ok(words[usize::from_le_bytes(buffer) % words.len()])
                })
                .collect::<Result<Vec<_>, Error>>()?
                .join(" ");
            eprintln!("Your passphrase is: {phrase}");
            loop {
                let typed = Password::new()
                    .with_prompt("Please try to type in this phrase")
                    .interact()?;
                if typed == phrase {
                    eprintln!("Correct, creating a database protected with this passphrase now.");
                    break;
                } else {
                    eprintln!("You appear to have mistyped the phrase, please try again.");
                }
            }
            phrase
        } else {
            Password::new()
                .with_prompt("Main password for the database")
                .with_confirmation("Confirm password", "Passwords don't match")
                .interact()?
        }
    };

    let file = std::fs::File::create(path)?;
    let mut writer = std::io::BufWriter::new(file);
    keepass_db::Database::save_new(&mut writer, &main_password, kdf_parameters)?;
    Ok(())
}

fn add_database() -> Result<(), Error> {
    let selection = Select::new()
        .with_prompt("If you already have a KeePass database, this application can use it")
        .items(&["Add an existing database", "Create a new database"])
        .default(0)
        .interact_opt()?
        .ok_or(Error::Aborted)?;

    let path = if selection == 0 {
        let path = choose_path(false)?;
        if !try_database(&path) {
            return Ok(());
        }
        path
    } else {
        let path = choose_path(true)?;
        create_database(&path)?;
        path
    };

    let (mut databases, default) = get_databases();
    let mut name;
    loop {
        name = Input::new()
            .with_prompt("Enter a name for this database")
            .default("Passwords".to_string())
            .interact_text()?;
        if databases.iter().any(|(n, _)| n == &name) {
            eprintln!("This database name already exists, please choose another.");
        } else {
            break;
        }
    }

    databases.push((name, path));
    save_databases(databases, default)
}

fn remove_database() -> Result<(), Error> {
    let (mut databases, default) = get_databases();
    let items = databases
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    let selection = Select::new()
        .with_prompt("Please choose a database to remove from the list")
        .items(&items)
        .default(0)
        .interact_opt()?
        .ok_or(Error::Aborted)?;
    databases.swap_remove(selection);
    save_databases(databases, default)
}

fn choose_default_database() -> Result<(), Error> {
    let (databases, _) = get_databases();
    let items = databases
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    let selection = Select::new()
        .with_prompt("Please choose a database to be the default")
        .items(&items)
        .default(0)
        .interact_opt()?
        .ok_or(Error::Aborted)?;

    let default = databases[selection].0.clone();
    save_databases(databases, default)
}

fn ignore_abort(result: Result<(), Error>) -> Result<(), Error> {
    match result {
        Err(Error::Aborted) => Ok(()),
        other => other,
    }
}

fn setup_databases() -> Result<(), Error> {
    let (databases, default) = get_databases();
    if databases.is_empty() {
        eprintln!("No databases configured, you need to add a database.");
        add_database()?;
        setup_databases()
    } else {
        eprintln!();
        eprintln!("Currently configured databases:");
        for (name, path) in databases.iter() {
            if name == &default {
                eprintln!("{name}: {} [default]", path.display());
            } else {
                eprintln!("{name}: {}", path.display());
            }
        }

        eprintln!();
        let selection = Select::new()
            .with_prompt("Choose an action")
            .items(&[
                "Continue to browser configuration",
                "Add a database",
                "Remove a database",
                "Choose default database",
            ])
            .default(0)
            .interact_opt()?
            .ok_or(Error::Aborted)?;

        if selection == 1 {
            ignore_abort(add_database())?;
            setup_databases()
        } else if selection == 2 {
            ignore_abort(remove_database())?;
            setup_databases()
        } else if selection == 3 {
            ignore_abort(choose_default_database())?;
            setup_databases()
        } else {
            setup_browsers()
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
        eprintln!();
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
    if args.len() >= 2 {
        native_host::run_server()
    } else {
        setup_databases()
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
