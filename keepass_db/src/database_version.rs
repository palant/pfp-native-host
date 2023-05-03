use std::io::{Read, Write};

use crate::io::{Deserialize, Serialize};
use crate::Error;

const SIGNATURE1: u32 = 0x9AA2D903;
const SIGNATURE2: u32 = 0xB54BFB67;

/// Represents the KeePass database version
#[derive(Debug, PartialEq)]
pub struct DatabaseVersion {
    /// Major version part
    pub major: u16,
    /// Minor version part
    pub minor: u16,
}

impl std::fmt::Display for DatabaseVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

impl Default for DatabaseVersion {
    fn default() -> Self {
        Self { major: 4, minor: 0 }
    }
}

impl Serialize for DatabaseVersion {
    fn serialize<W: Write>(&self, output: &mut W) -> Result<(), Error> {
        SIGNATURE1.serialize(output)?;
        SIGNATURE2.serialize(output)?;
        self.minor.serialize(output)?;
        self.major.serialize(output)?;
        Ok(())
    }
}

impl Deserialize for DatabaseVersion {
    fn deserialize<R: Read>(input: &mut R) -> Result<Self, Error> {
        let signature1 = u32::deserialize(input)?;
        let signature2 = u32::deserialize(input)?;
        if signature1 != SIGNATURE1 || signature2 != SIGNATURE2 {
            return Err(Error::CorruptDatabase);
        }

        let minor = u16::deserialize(input)?;
        let major = u16::deserialize(input)?;
        let version = Self { major, minor };
        if major != 4 {
            return Err(Error::UnsupportedVersion(version));
        }

        Ok(version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use std::io::Cursor;

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", DatabaseVersion { major: 4, minor: 1 }), "4.1");
        assert_eq!(format!("{}", DatabaseVersion::default()), "4.0")
    }

    #[test]
    fn test_deserialize() {
        fn deserialize<T: AsRef<[u8]>>(data: T) -> Result<DatabaseVersion, Error> {
            let mut cursor = Cursor::new(data);
            DatabaseVersion::deserialize(&mut cursor)
        }

        assert!(matches!(
            deserialize(hex!("01 02 03 04   05 06 07 08   01 00 04 00"))
                .expect_err("Deserializing invalid file signature"),
            Error::CorruptDatabase
        ));

        assert_eq!(
            deserialize(hex!("03 d9 a2 9a   67 fb 4b b5   01 00 04 00"))
                .expect("Deserializing correct database version"),
            DatabaseVersion { major: 4, minor: 1 }
        );
    }

    #[test]
    fn test_serialize() {
        let mut vec = Vec::new();
        DatabaseVersion { major: 4, minor: 1 }
            .serialize(&mut vec)
            .unwrap();

        assert_eq!(vec, hex!("03 d9 a2 9a   67 fb 4b b5   01 00 04 00"));
    }
}
