const NATIVE_APP_ID: &str = "works.pfp.pfp_native_host";
const CONFIG_FILE: &str = const_format::concatcp!(NATIVE_APP_ID, ".json");

error_enum::declare! {
    pub(crate) enum BrowserSetupError {
        ///Home directory could not be determined
        NoHomeDirectory,
        ///Current process path could not be determined
        NoProcessPath,
        Io(std::io::Error),
        Json(serde_json::Error),
    }
}

macro_rules! declare_enum {
    {
        $visibility:vis $type:ident {
            $(
                #[doc=$doc:literal]
                $variant:ident,
            )*
        }
    } => {
        #[derive(Debug)]
        $visibility enum $type {
            $(
                #[doc=$doc]
                $variant,
            )*
        }

        const ALL: &[$type] = &[
            $($type::$variant,)*
        ];

        impl $type {
            pub fn all() -> &'static [Self] {
                ALL
            }

            pub fn name(&self) -> &'static str {
                match self {
                    $(
                        Self::$variant => $doc,
                    )*
                }
            }
        }

        impl std::fmt::Display for $type {
            fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(fmt, "{}", self.name())
            }
        }
    }
}

declare_enum! {
    pub(crate) Browser {
        ///Mozilla Firefox
        Firefox,
        ///Google Chrome
        Chrome,
        ///Chromium
        Chromium,
        ///Opera
        Opera,
        ///Vivaldi
        Vivaldi,
        ///Microsoft Edge
        Edge,
    }
}

impl Browser {
    #[cfg(unix)]
    fn home_dir() -> Option<std::path::PathBuf> {
        #[allow(deprecated)]
        std::env::home_dir()
    }

    #[cfg(target_os = "linux")]
    fn get_config_root(&self) -> Result<std::path::PathBuf, BrowserSetupError> {
        let mut root = Self::home_dir().ok_or(BrowserSetupError::NoHomeDirectory)?;
        root.push(".config");
        match self {
            Self::Firefox => {
                root.pop();
                root.push(".mozilla");
            }
            Self::Chrome | Self::Opera => {
                root.push("google-chrome");
            }
            Self::Chromium => {
                root.push("chromium");
            }
            Self::Vivaldi => {
                root.push("vivaldi");
            }
            Self::Edge => {
                root.push("microsoft-edge");
            }
        };

        if let Self::Firefox = self {
            root.push("native-messaging-hosts");
        } else {
            root.push("NativeMessagingHosts");
        }

        Ok(root)
    }

    #[cfg(target_os = "macos")]
    fn get_config_root(&self) -> Result<std::path::PathBuf, BrowserSetupError> {
        let mut root = Self::home_dir().ok_or(BrowserSetupError::NoHomeDirectory)?;
        root.push("Library");
        root.push("Application Support");
        match self {
            Self::Firefox => {
                root.push("Mozilla");
            }
            Self::Chrome | Self::Opera => {
                root.push("Google");
                root.push("Chrome");
            }
            Self::Chromium => {
                root.push("Chromium");
            }
            Self::Vivaldi => {
                root.push("Vivaldi");
            }
            Self::Edge => {
                root.push("Microsoft Edge");
            }
        };
        root.push("NativeMessagingHosts");
        Ok(root)
    }

    #[cfg(unix)]
    fn get_config_path(&self, path: &str) -> Result<std::path::PathBuf, BrowserSetupError> {
        let mut result = self.get_config_root()?;
        for part in path.split('/') {
            result.push(part);
        }
        Ok(result)
    }

    #[cfg(unix)]
    pub fn is_configured(&self) -> bool {
        if let Ok(path) = self.get_config_path(CONFIG_FILE) {
            path.exists()
        } else {
            false
        }
    }

    #[cfg(unix)]
    pub fn configure(&self, extension_id: &str) -> Result<(), BrowserSetupError> {
        let path = self.get_config_path(CONFIG_FILE)?;
        let executable = std::env::current_exe()?;
        let executable_path = executable
            .as_os_str()
            .to_str()
            .ok_or(BrowserSetupError::NoProcessPath)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut writer = std::fs::File::create(path)?;
        let allowed_key = if let Self::Firefox = self {
            "allowed_extensions"
        } else {
            "allowed_origins"
        };
        serde_json::to_writer_pretty(
            &mut writer,
            &serde_json::json!({
                allowed_key: [extension_id],
                "description": "Native messaging host providing browser extensions access to a KeePass database file",
                "name": NATIVE_APP_ID,
                "path": executable_path,
                "type": "stdio",
            }),
        )?;
        Ok(())
    }

    pub fn extension_id(&self) -> &'static str {
        match self {
            Self::Firefox => "pfp@pfp.works",
            // TODO: Change this once the extension is released
            _ => "chrome-extension://kpcjmfjmknbolfjjemmbpnajbiehajac/",
        }
    }
}
