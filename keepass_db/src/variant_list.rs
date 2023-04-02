use std::io::{Read, Write};

use super::{Error, VariantField, VariantType, VariantValue};
use crate::io::{Deserialize, Serialize};

const VERSION: u16 = 0x0100;

#[derive(Debug)]
pub(crate) struct VariantList {
    list: Vec<VariantField>,
}

impl VariantList {
    pub fn new() -> Self {
        Self { list: Vec::new() }
    }

    pub fn len(&self) -> usize {
        let mut result = (u16::BITS / 8) as usize; // VERSION
        for field in &self.list {
            result += field.len();
        }
        result += VariantType::SIZE; // EndOfList
        result
    }

    pub fn add(&mut self, key: &str, value: VariantValue) {
        self.list.push(VariantField {
            key: key.to_string(),
            value,
        })
    }

    pub fn get(&self, key: &str) -> Option<VariantValue> {
        for field in &self.list {
            if field.key == key {
                return Some(field.value.clone());
            }
        }
        None
    }
}

impl Serialize for VariantList {
    fn serialize<W: Write>(&self, output: &mut W) -> Result<(), Error> {
        VERSION.serialize(output)?;
        for field in &self.list {
            field.serialize(output)?;
        }
        VariantField {
            key: String::new(),
            value: VariantValue::EndOfList,
        }
        .serialize(output)?;
        Ok(())
    }
}

impl Deserialize for VariantList {
    fn deserialize<R: Read>(input: &mut R) -> Result<Self, Error> {
        let version = u16::deserialize(input)?;
        if version & 0xFF00 > VERSION {
            return Err(Error::UnsupportedVariantListVersion(version));
        }

        let mut list = Vec::new();
        loop {
            let field = VariantField::deserialize(input)?;
            if let VariantValue::EndOfList = field.value {
                return Ok(Self { list });
            }
            list.push(field);
        }
    }
}
