error_enum::declare! {
    pub(crate) enum Error {
        Db(keepass_db::Error{std::io::Error, xmltree::Error}),
        Json(serde_json::Error),
        BrowserSetup(crate::browser_support::BrowserSetupError),
        AppDir(app_dirs2::AppDirsError),
        Dialog(native_dialog::Error),
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
