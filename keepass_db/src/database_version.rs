use std::io::{Read, Write};

use crate::io::{Deserialize, Serialize};
use crate::Error;

const SIGNATURE1: u32 = 0x9AA2D903;
const SIGNATURE2: u32 = 0xB54BFB67;

#[derive(Debug, PartialEq)]
pub struct DatabaseVersion {
    pub major: u16,
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
