use std::io::{Read, Write};

use crate::io::{Deserialize, DeserializeWithSize, Serialize};
use crate::Error;

/// Holds the data of a binary attachment
#[derive(Debug, PartialEq)]
pub(crate) struct Binary {
    /// Attachment flags, 0x01 indicates that memory protection should be enabled (ignored).
    flags: u8,

    /// Binary file data
    data: Vec<u8>,
}

impl Binary {
    /// Calculates the size of this data structure when serialized in a KeePass database.
    pub fn len(&self) -> usize {
        (u8::BITS / 8) as usize + self.data.len()
    }
}

impl Serialize for Binary {
    fn serialize<W: Write>(&self, output: &mut W) -> Result<(), Error> {
        self.flags.serialize(output)?;
        self.data.serialize(output)
    }
}

impl DeserializeWithSize for Binary {
    fn deserialize<R: Read>(input: &mut R, size: usize) -> Result<Self, Error> {
        if size < 1 {
            return Err(Error::InvalidFieldSize);
        }

        let flags = u8::deserialize(input)?;
        if flags & !0x01 != 0 {
            return Err(Error::UnsupportedBinaryFlags(flags));
        }

        let data = Vec::deserialize(input, size - 1)?;
        Ok(Self { flags, data })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use std::io::Cursor;

    fn deserialize<const SIZE: usize>(data: [u8; SIZE]) -> Result<Binary, Error> {
        let mut cursor = Cursor::new(data);
        Binary::deserialize(&mut cursor, SIZE)
    }

    fn serialize(binary: Binary) -> Result<Vec<u8>, Error> {
        let mut result = Vec::new();
        binary.serialize(&mut result)?;
        Ok(result)
    }

    #[test]
    fn test_deserialize() {
        assert!(matches!(
            deserialize(hex!("")).expect_err("Deserializing empty data"),
            Error::InvalidFieldSize
        ));

        assert!(matches!(
            deserialize(hex!("03")).expect_err("Deserializing invalid flag"),
            Error::UnsupportedBinaryFlags(0x03)
        ));

        assert_eq!(
            deserialize(hex!("00")).expect("Deserializing flag only"),
            Binary {
                flags: 0x00,
                data: vec![],
            }
        );

        assert_eq!(
            deserialize(hex!("01 02 03 04")).expect("Deserializing flag with data"),
            Binary {
                flags: 0x01,
                data: hex!("02 03 04").to_vec(),
            }
        );
    }

    #[test]
    fn test_serialize() {
        assert_eq!(
            serialize(Binary {
                flags: 0x00,
                data: vec![],
            })
            .expect("Serializing flag only"),
            hex!("00"),
        );

        assert_eq!(
            Binary {
                flags: 0x00,
                data: vec![],
            }
            .len(),
            hex!("00").len(),
        );

        assert_eq!(
            serialize(Binary {
                flags: 0x01,
                data: hex!("02 03 04").to_vec(),
            })
            .expect("Serializing flag with data"),
            hex!("01 02 03 04"),
        );

        assert_eq!(
            Binary {
                flags: 0x01,
                data: hex!("02 03 04").to_vec(),
            }
            .len(),
            hex!("01 02 03 04").len(),
        );
    }
}
