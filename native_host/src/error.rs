error_enum::declare! {
    pub(crate) enum Error {
        Db(keepass_db::Error{std::io::Error, xmltree::Error}),
        Json(serde_json::Error),
        BrowserSetup(crate::browser_support::BrowserSetupError),
        Dialog(native_dialog::Error),
        ///Failed determining location of the configuration file
        UnknownConfigLocation,
        ///A database file has not been configured
        Unconfigured,
        ///Message could not be processed
        InvalidMessage,
        ///A password with this title already exists
        EntryExists,
        ///Action has been aborted
        Aborted,
    }
}
