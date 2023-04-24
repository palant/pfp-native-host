error_enum::declare! {
    pub enum Error {
        Io(std::io::Error),
        Encoding(std::string::FromUtf8Error),
        XMLParsing(xmltree::ParseError),
        XMLSerialization(xmltree::Error),
        ///Key derivation failed
        KeyDerivation,
        ///The database file is either corrupt or not a supported KeePass database
        CorruptDatabase,
        ///Database version {} is not supported
        UnsupportedVersion(crate::DatabaseVersion),
        ///Encountered an unsupported header field type {}
        UnsupportedHeaderFieldType(u8),
        ///Encountered an invalid field size
        InvalidFieldSize,
        ///Encountered an unsupported block cipher type
        UnsupportedBlockCipher,
        ///Encountered an unsupported stream cipher type {}
        UnsupportedStreamCipher(u32),
        ///Encountered an unsupported compression type {:#x}
        UnsupportedCompression(u32),
        ///Encountered an unsupported variant map version {:#06x}
        UnsupportedVariantListVersion(u16),
        ///Encountered an unsupported variant type {:#04x}
        UnsupportedVariantType(u8),
        ///Key derivation field {} is missing or invalid
        KdfFieldMissingOrInvalid(&'static str),
        ///AES-KDF is not supported, please update your database
        AesKDFUnsupported,
        ///Encountered an unsupported KDF type
        UnsupportedKDF,
        ///KDF parameter value exceeds supported range
        KDFParameterExceedsRange,
        ///Database is missing header fields
        HeaderFieldsMissing,
        ///Database header has wrong checksum, probably a corrupt file
        HeaderChecksumMismatch,
        ///The credentials provided are invalid, please try again
        InvalidCredentials,
        ///Database data could not be encrypted
        EncryptionError,
        ///Database data could not be decrypted
        DecryptionError,
        ///Random number generation failed
        RandomNumberGeneratorFailed,
        ///Encountered unsupported binary attachment flags {:#04x}
        UnsupportedBinaryFlags(u8),
        ///Database is missing a root group or root group isn't searchable
        MissingRootGroup,
        ///Password entry not found
        NoSuchEntry,
    }
}

impl From<Error> for std::io::Error {
    fn from(error: Error) -> Self {
        if let Error::Io(error) = error {
            error
        } else {
            Self::new(std::io::ErrorKind::Other, format!("{error}"))
        }
    }
}
