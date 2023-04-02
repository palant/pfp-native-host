use std::io::{Read, Write};

use crate::error::Error;

pub trait Serialize {
    fn serialize<W>(&self, output: &mut W) -> Result<(), Error>
    where
        W: Write;
}

macro_rules! impl_serialize {
    ($type: ident) => {
        impl Serialize for $type {
            fn serialize<W: Write>(&self, output: &mut W) -> Result<(), Error> {
                output.write_all(&self.to_le_bytes())?;
                Ok(())
            }
        }
    };
}

impl_serialize!(u8);
impl_serialize!(u16);
impl_serialize!(u32);
impl_serialize!(u64);

impl_serialize!(i8);
impl_serialize!(i16);
impl_serialize!(i32);
impl_serialize!(i64);

impl Serialize for Vec<u8> {
    fn serialize<W: Write>(&self, output: &mut W) -> Result<(), Error> {
        output.write_all(self)?;
        Ok(())
    }
}

impl Serialize for [u8] {
    fn serialize<W: Write>(&self, output: &mut W) -> Result<(), Error> {
        output.write_all(self)?;
        Ok(())
    }
}

impl Serialize for String {
    fn serialize<W: Write>(&self, output: &mut W) -> Result<(), Error> {
        output.write_all(self.as_bytes())?;
        Ok(())
    }
}

pub trait Deserialize: Sized {
    fn deserialize<R>(input: &mut R) -> Result<Self, Error>
    where
        R: Read;
}

pub trait DeserializeWithSize: Sized {
    fn deserialize<R>(input: &mut R, size: usize) -> Result<Self, Error>
    where
        R: Read;
}

macro_rules! impl_deserialize {
    ($type: ident) => {
        impl Deserialize for $type {
            fn deserialize<R: Read>(input: &mut R) -> Result<Self, Error> {
                let mut buffer = [0; (Self::BITS / 8) as usize];
                input.read_exact(&mut buffer)?;
                Ok(Self::from_le_bytes(buffer))
            }
        }
    };
}

impl_deserialize!(u8);
impl_deserialize!(u16);
impl_deserialize!(u32);
impl_deserialize!(u64);

impl_deserialize!(i8);
impl_deserialize!(i16);
impl_deserialize!(i32);
impl_deserialize!(i64);

impl DeserializeWithSize for Vec<u8> {
    fn deserialize<R: Read>(input: &mut R, size: usize) -> Result<Self, Error> {
        let mut buffer = Vec::new();
        buffer.resize(size, 0);
        input.read_exact(&mut buffer)?;
        Ok(buffer)
    }
}

impl DeserializeWithSize for String {
    fn deserialize<R: Read>(input: &mut R, size: usize) -> Result<Self, Error> {
        let vector = Vec::deserialize(input, size)?;
        Ok(String::from_utf8(vector)?)
    }
}
