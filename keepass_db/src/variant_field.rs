use std::io::{Read, Write};

use crate::io::{Deserialize, DeserializeWithSize, Serialize};
use crate::{numeric_enum, Error};

numeric_enum!(VariantType=u8(UnsupportedVariantType) {
    EndOfList = 0x00,
    U32 = 0x04,
    U64 = 0x05,
    Bool = 0x08,
    I32 = 0x0C,
    I64 = 0x0D,
    String = 0x18,
    Bytes = 0x42,
});

#[derive(Debug, Clone)]
pub(crate) enum VariantValue {
    EndOfList,
    U32(u32),
    U64(u64),
    Bool(bool),
    I32(i32),
    I64(i64),
    String(String),
    Bytes(Vec<u8>),
}

impl VariantValue {
    pub fn len(&self) -> usize {
        match self {
            Self::EndOfList => 0,
            Self::U32(_) => (u32::BITS / 8) as usize,
            Self::U64(_) => (u64::BITS / 8) as usize,
            Self::Bool(_) => (u8::BITS / 8) as usize,
            Self::I32(_) => (i32::BITS / 8) as usize,
            Self::I64(_) => (i64::BITS / 8) as usize,
            Self::String(value) => value.len(),
            Self::Bytes(value) => value.len(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct VariantField {
    pub key: String,
    pub value: VariantValue,
}

impl VariantField {
    pub fn len(&self) -> usize {
        if let VariantValue::EndOfList = self.value {
            VariantType::SIZE
        } else {
            VariantType::SIZE + (u32::BITS * 2 / 8) as usize + self.key.len() + self.value.len()
        }
    }
}

impl Serialize for VariantField {
    fn serialize<W: Write>(&self, output: &mut W) -> Result<(), Error> {
        match &self.value {
            VariantValue::EndOfList => return VariantType::EndOfList.serialize(output),
            VariantValue::U32(_) => VariantType::U32,
            VariantValue::U64(_) => VariantType::U64,
            VariantValue::Bool(_) => VariantType::Bool,
            VariantValue::I32(_) => VariantType::I32,
            VariantValue::I64(_) => VariantType::I64,
            VariantValue::String(_) => VariantType::String,
            VariantValue::Bytes(_) => VariantType::Bytes,
        }
        .serialize(output)?;

        (self.key.len() as u32).serialize(output)?;
        self.key.serialize(output)?;

        match &self.value {
            VariantValue::EndOfList => Ok(()),
            VariantValue::U32(value) => {
                (u32::BITS / 8).serialize(output)?;
                value.serialize(output)
            }
            VariantValue::U64(value) => {
                (u64::BITS / 8).serialize(output)?;
                value.serialize(output)
            }
            VariantValue::Bool(value) => {
                (u8::BITS / 8).serialize(output)?;
                if *value { 0x01u8 } else { 0x00u8 }.serialize(output)
            }
            VariantValue::I32(value) => {
                (i32::BITS / 8).serialize(output)?;
                value.serialize(output)
            }
            VariantValue::I64(value) => {
                (i64::BITS / 8).serialize(output)?;
                value.serialize(output)
            }
            VariantValue::String(value) => {
                (value.len() as u32).serialize(output)?;
                value.serialize(output)
            }
            VariantValue::Bytes(value) => {
                (value.len() as u32).serialize(output)?;
                value.serialize(output)
            }
        }
    }
}

impl Deserialize for VariantField {
    fn deserialize<R: Read>(input: &mut R) -> Result<Self, Error> {
        let variant_type = VariantType::deserialize(input)?;
        if let VariantType::EndOfList = variant_type {
            return Ok(Self {
                key: String::new(),
                value: VariantValue::EndOfList,
            });
        }

        let (key, size) = if let VariantType::EndOfList = variant_type {
            // No key or value stored for EndOfList
            (String::new(), 0)
        } else {
            let key_size = u32::deserialize(input)? as usize;
            (
                String::deserialize(input, key_size)?,
                u32::deserialize(input)?,
            )
        };

        Ok(Self {
            key,
            value: match variant_type {
                VariantType::EndOfList => VariantValue::EndOfList,
                VariantType::U32 => {
                    if size != u32::BITS / 8 {
                        return Err(Error::InvalidFieldSize);
                    }
                    VariantValue::U32(u32::deserialize(input)?)
                }
                VariantType::U64 => {
                    if size != u64::BITS / 8 {
                        return Err(Error::InvalidFieldSize);
                    }
                    VariantValue::U64(u64::deserialize(input)?)
                }
                VariantType::Bool => {
                    if size != u8::BITS / 8 {
                        return Err(Error::InvalidFieldSize);
                    }
                    VariantValue::Bool(u8::deserialize(input)? != 0)
                }
                VariantType::I32 => {
                    if size != i32::BITS / 8 {
                        return Err(Error::InvalidFieldSize);
                    }
                    VariantValue::I32(i32::deserialize(input)?)
                }
                VariantType::I64 => {
                    if size != i64::BITS / 8 {
                        return Err(Error::InvalidFieldSize);
                    }
                    VariantValue::I64(i64::deserialize(input)?)
                }
                VariantType::String => {
                    VariantValue::String(String::deserialize(input, size as usize)?)
                }
                VariantType::Bytes => VariantValue::Bytes(Vec::deserialize(input, size as usize)?),
            },
        })
    }
}
