use std::io::{Read, Write};

use crate::io::{Deserialize, DeserializeWithSize, Serialize};
use crate::Error;

#[derive(Debug)]
pub(crate) struct Binary {
    flags: u8,
    data: Vec<u8>,
}

impl Binary {
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
