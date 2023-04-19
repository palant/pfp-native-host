use std::io::{Read, Write};

use crate::io::{Deserialize, DeserializeWithSize, Serialize};
use crate::{
    Binary, BlockCipher, Compression, Error, InnerHeaderFieldType, KdfParameters,
    OuterHeaderFieldType, StreamCipher, VariantList,
};

#[derive(Debug)]
pub struct OuterHeader {
    pub(crate) cipher: BlockCipher,
    pub(crate) compression: Compression,
    pub(crate) main_seed: Vec<u8>,
    pub(crate) iv: Vec<u8>,
    pub(crate) kdf_parameters: KdfParameters,
    pub(crate) custom_data: Option<VariantList>,
}

impl OuterHeader {
    pub fn new(kdf_parameters: KdfParameters) -> Result<Self, Error> {
        let cipher = BlockCipher::default();
        let iv_size = cipher.iv_size();
        Ok(Self {
            cipher,
            compression: Default::default(),
            main_seed: crate::random::random_vec(32)?,
            iv: crate::random::random_vec(iv_size)?,
            kdf_parameters,
            custom_data: Default::default(),
        })
    }

    pub fn reset_iv(&mut self) -> Result<(), Error> {
        self.iv = crate::random::random_vec(self.cipher.iv_size())?;
        Ok(())
    }
}

impl Serialize for OuterHeader {
    fn serialize<W: Write>(&self, output: &mut W) -> Result<(), Error> {
        OuterHeaderFieldType::Cipher.serialize(output)?;
        (BlockCipher::SIZE as u32).serialize(output)?;
        self.cipher.serialize(output)?;

        OuterHeaderFieldType::Compression.serialize(output)?;
        (Compression::SIZE as u32).serialize(output)?;
        self.compression.serialize(output)?;

        OuterHeaderFieldType::MainSeed.serialize(output)?;
        (self.main_seed.len() as u32).serialize(output)?;
        self.main_seed.serialize(output)?;

        OuterHeaderFieldType::InitializationVector.serialize(output)?;
        (self.iv.len() as u32).serialize(output)?;
        self.iv.serialize(output)?;

        OuterHeaderFieldType::KdfParameters.serialize(output)?;
        let list = VariantList::from(&self.kdf_parameters);
        (list.len() as u32).serialize(output)?;
        list.serialize(output)?;

        if let Some(custom_data) = &self.custom_data {
            OuterHeaderFieldType::CustomData.serialize(output)?;
            (custom_data.len() as u32).serialize(output)?;
            custom_data.serialize(output)?;
        }

        OuterHeaderFieldType::EndOfHeader.serialize(output)?;
        let buffer = b"\r\n\r\n";
        (buffer.len() as u32).serialize(output)?;
        buffer.serialize(output)?;

        Ok(())
    }
}

impl Deserialize for OuterHeader {
    fn deserialize<R: Read>(input: &mut R) -> Result<Self, Error> {
        let mut cipher = None;
        let mut compression = None;
        let mut main_seed = None;
        let mut iv = None;
        let mut kdf_parameters = None;
        let mut custom_data = None;

        loop {
            let field_type = OuterHeaderFieldType::deserialize(input)?;
            let size = u32::deserialize(input)? as usize;
            match field_type {
                OuterHeaderFieldType::Comment => {
                    // Ignore comments, KeePass and KeePassXC do as well
                    Vec::deserialize(input, size)?;
                }
                OuterHeaderFieldType::Cipher => {
                    if size != BlockCipher::SIZE {
                        return Err(Error::InvalidFieldSize);
                    }
                    cipher = Some(BlockCipher::deserialize(input)?);
                }
                OuterHeaderFieldType::Compression => {
                    if size != Compression::SIZE {
                        return Err(Error::InvalidFieldSize);
                    }
                    compression = Some(Compression::deserialize(input)?);
                }
                OuterHeaderFieldType::MainSeed => {
                    main_seed = Some(Vec::deserialize(input, size)?);
                }
                OuterHeaderFieldType::InitializationVector => {
                    iv = Some(Vec::deserialize(input, size)?);
                }
                OuterHeaderFieldType::KdfParameters => {
                    let list = VariantList::deserialize(input)?;
                    if list.len() != size {
                        return Err(Error::InvalidFieldSize);
                    }
                    kdf_parameters = Some(KdfParameters::try_from(list)?);
                }
                OuterHeaderFieldType::CustomData => {
                    let list = VariantList::deserialize(input)?;
                    if list.len() != size {
                        return Err(Error::InvalidFieldSize);
                    }
                    custom_data = Some(list);
                }
                OuterHeaderFieldType::EndOfHeader => {
                    Vec::deserialize(input, size)?;
                    break;
                }
            }
        }

        Ok(Self {
            cipher: cipher.ok_or(Error::HeaderFieldsMissing)?,
            compression: compression.ok_or(Error::HeaderFieldsMissing)?,
            main_seed: main_seed.ok_or(Error::HeaderFieldsMissing)?,
            iv: iv.ok_or(Error::HeaderFieldsMissing)?,
            kdf_parameters: kdf_parameters.ok_or(Error::HeaderFieldsMissing)?,
            custom_data,
        })
    }
}

#[derive(Debug, Default)]
pub(crate) struct InnerHeader {
    pub cipher: StreamCipher,
    pub key: Vec<u8>,
    pub binaries: Vec<Binary>,
}

impl InnerHeader {
    pub fn reset_cipher(&mut self) -> Result<(), Error> {
        self.cipher = StreamCipher::ChaCha20;
        self.key = crate::random::random_vec(self.cipher.key_size())?;
        Ok(())
    }
}

impl Serialize for InnerHeader {
    fn serialize<W: Write>(&self, output: &mut W) -> Result<(), Error> {
        InnerHeaderFieldType::StreamCipher.serialize(output)?;
        (StreamCipher::SIZE as u32).serialize(output)?;
        self.cipher.serialize(output)?;

        InnerHeaderFieldType::StreamKey.serialize(output)?;
        (self.key.len() as u32).serialize(output)?;
        self.key.serialize(output)?;

        for binary in &self.binaries {
            InnerHeaderFieldType::Binary.serialize(output)?;
            (binary.len() as u32).serialize(output)?;
            binary.serialize(output)?;
        }

        InnerHeaderFieldType::EndOfHeader.serialize(output)?;
        let buffer = b"";
        (buffer.len() as u32).serialize(output)?;
        buffer.serialize(output)?;

        Ok(())
    }
}

impl Deserialize for InnerHeader {
    fn deserialize<R: Read>(input: &mut R) -> Result<Self, Error> {
        let mut cipher = None;
        let mut key = None;
        let mut binaries = Vec::new();

        loop {
            let field_type = InnerHeaderFieldType::deserialize(input)?;
            let size = u32::deserialize(input)? as usize;
            match field_type {
                InnerHeaderFieldType::StreamCipher => {
                    if size != StreamCipher::SIZE {
                        return Err(Error::InvalidFieldSize);
                    }
                    cipher = Some(StreamCipher::deserialize(input)?);
                }
                InnerHeaderFieldType::StreamKey => {
                    key = Some(Vec::deserialize(input, size)?);
                }
                InnerHeaderFieldType::Binary => {
                    binaries.push(Binary::deserialize(input, size)?);
                }
                InnerHeaderFieldType::EndOfHeader => {
                    Vec::deserialize(input, size)?;
                    break;
                }
            }
        }

        Ok(Self {
            cipher: cipher.ok_or(Error::HeaderFieldsMissing)?,
            key: key.ok_or(Error::HeaderFieldsMissing)?,
            binaries,
        })
    }
}
