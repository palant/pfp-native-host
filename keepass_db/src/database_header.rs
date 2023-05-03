use std::io::{Read, Write};

use crate::io::{Deserialize, DeserializeWithSize, Serialize};
use crate::{
    Binary, BlockCipher, Compression, Error, InnerHeaderFieldType, KdfParameters,
    OuterHeaderFieldType, StreamCipher, VariantList,
};

/// Represents the outer (unencrypted) header of the KeePass database
#[derive(Debug)]
pub struct OuterHeader {
    /// Cipher used to encrypt the database
    pub(crate) cipher: BlockCipher,
    /// Compression type of the database
    pub(crate) compression: Compression,
    /// Main seed used to derive the key
    pub(crate) main_seed: Vec<u8>,
    /// Initialization vector for the encryption
    pub(crate) iv: Vec<u8>,
    /// Key derivation parameters
    pub(crate) kdf_parameters: KdfParameters,
    /// Custom data added by KeePass plugins
    pub(crate) custom_data: Option<VariantList>,
}

impl OuterHeader {
    /// Creates the outer header for a new database. Key derivation parameters
    /// are passed in, otherwise the defaults are used: ChaCha20 encryption and
    /// Gzip compression, random main seed and initialization vector.
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

    /// Resets the initialization vector to a new random value before saving
    /// the database.
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

        // KeePass and KeePassXC serialize EndOfHeader with four bytes of
        // data, match their behavior.
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

/// Represents the inner (encrypted) header of the database.
#[derive(Debug, Default)]
pub(crate) struct InnerHeader {
    /// The cipher used for protected values
    pub cipher: StreamCipher,
    /// The key used for protected values
    pub key: Vec<u8>,
    /// Attached binary files
    pub binaries: Vec<Binary>,
}

impl InnerHeader {
    /// Resets cipher and key for protected values before saving the database.
    /// Cipher will always be ChaCha20 then.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VariantValue;
    use hex_literal::hex;
    use std::io::Cursor;

    fn serialize<S: Serialize>(input: &S) -> Vec<u8> {
        let mut vec = Vec::new();
        input.serialize(&mut vec).unwrap();
        vec
    }

    #[test]
    fn test_outer_new() {
        let mut header = OuterHeader::new(KdfParameters {
            algorithm: argon2::Variant::ID,
            version: argon2::Version::Version10,
            salt: vec![0; 16],
            parallelism: 8,
            memory: 1024,
            iterations: 4,
        })
        .expect("Creating a new outer header");

        assert_eq!(header.cipher, BlockCipher::ChaCha20);
        assert_eq!(header.compression, Compression::Gzip);
        assert!(matches!(
            header.kdf_parameters.algorithm,
            argon2::Variant::ID
        ));
        assert!(matches!(
            header.kdf_parameters.version,
            argon2::Version::Version10
        ));
        assert_eq!(header.kdf_parameters.salt, vec![0; 16]);
        assert_eq!(header.kdf_parameters.parallelism, 8);
        assert_eq!(header.kdf_parameters.memory, 1024);
        assert_eq!(header.kdf_parameters.iterations, 4);
        assert_eq!(header.custom_data, None);

        let iv = header.iv.clone();
        header.reset_iv().expect("Resetting initialization vector");

        assert_ne!(header.iv, iv);
        assert_eq!(header.cipher, BlockCipher::ChaCha20);
        assert_eq!(header.compression, Compression::Gzip);
        assert!(matches!(
            header.kdf_parameters.algorithm,
            argon2::Variant::ID
        ));
        assert!(matches!(
            header.kdf_parameters.version,
            argon2::Version::Version10
        ));
        assert_eq!(header.kdf_parameters.salt, vec![0; 16]);
        assert_eq!(header.kdf_parameters.parallelism, 8);
        assert_eq!(header.kdf_parameters.memory, 1024);
        assert_eq!(header.kdf_parameters.iterations, 4);
        assert_eq!(header.custom_data, None);
    }

    #[test]
    fn test_outer_deserialize() {
        fn deserialize<T: AsRef<[u8]>>(data: T) -> Result<OuterHeader, Error> {
            let mut cursor = Cursor::new(data);
            OuterHeader::deserialize(&mut cursor)
        }

        assert!(matches!(
            deserialize(hex!("88")).expect_err("Deserializing invalid field type"),
            Error::UnsupportedHeaderFieldType(0x88)
        ));

        assert!(matches!(
            deserialize(hex!("02 0A 00 00 00"))
                .expect_err("Deserializing invalid cipher ID field size"),
            Error::InvalidFieldSize
        ));

        assert!(matches!(
            deserialize(hex!("03 02 00 00 00"))
                .expect_err("Deserializing invalid compression field size"),
            Error::InvalidFieldSize
        ));

        assert!(matches!(
            deserialize(hex!("02 10 00 00 00 31c1f2e6 bf71 4350 be58 05216afc5aff"))
                .expect_err("Deserializing without end of header"),
            Error::Io(_)
        ));

        assert!(matches!(
            deserialize(hex!(
                "02 10 00 00 00 31c1f2e6 bf71 4350 be58 05216afc5aff 00 00 00 00 00"
            ))
            .expect_err("Deserializing with fields missing"),
            Error::HeaderFieldsMissing
        ));

        let mut buffer = Vec::new();
        buffer.extend_from_slice(&hex!("01   04 00 00 00   01 02 03 04"));

        buffer.extend_from_slice(&hex!("02   10 00 00 00"));
        buffer.append(&mut serialize(&BlockCipher::Aes256));

        buffer.extend_from_slice(&hex!("03   04 00 00 00"));
        buffer.append(&mut serialize(&Compression::Gzip));

        buffer.extend_from_slice(&hex!("04   08 00 00 00   01 02 03 04 05 06 07 08"));
        buffer.extend_from_slice(&hex!("07   08 00 00 00   08 07 06 05 04 03 02 01"));

        {
            let mut parameter = serialize(&VariantList::from(&KdfParameters {
                algorithm: argon2::Variant::ID,
                version: argon2::Version::Version10,
                salt: vec![0; 16],
                parallelism: 8,
                memory: 1024,
                iterations: 4,
            }));
            buffer.extend_from_slice(&hex!("0b"));
            buffer.extend_from_slice(&(parameter.len() as u32).to_le_bytes());
            buffer.append(&mut parameter);
        }

        {
            let mut custom = VariantList::new();
            custom.add("test", VariantValue::U32(0x1234));

            let mut parameter = serialize(&custom);
            buffer.extend_from_slice(&hex!("0c"));
            buffer.extend_from_slice(&(parameter.len() as u32).to_le_bytes());
            buffer.append(&mut parameter);
        }

        buffer.extend_from_slice(&hex!("00   04 00 00 00   0d 0a 0d 0a"));

        let header = deserialize(buffer).expect("Deserializing a complete outer header");
        assert_eq!(header.cipher, BlockCipher::Aes256);
        assert_eq!(header.compression, Compression::Gzip);
        assert_eq!(header.main_seed, hex!("01 02 03 04 05 06 07 08"));
        assert_eq!(header.iv, hex!("08 07 06 05 04 03 02 01"));
        assert!(matches!(
            header.kdf_parameters.algorithm,
            argon2::Variant::ID
        ));
        assert!(matches!(
            header.kdf_parameters.version,
            argon2::Version::Version10
        ));
        assert_eq!(header.kdf_parameters.salt, vec![0; 16]);
        assert_eq!(header.kdf_parameters.parallelism, 8);
        assert_eq!(header.kdf_parameters.memory, 1024);
        assert_eq!(header.kdf_parameters.iterations, 4);
        assert_eq!(
            header
                .custom_data
                .expect("Custom data")
                .get("test")
                .expect("Custom data value"),
            VariantValue::U32(0x1234)
        );
    }

    #[test]
    fn test_outer_serialize() {
        let mut header = OuterHeader::new(KdfParameters {
            algorithm: argon2::Variant::ID,
            version: argon2::Version::Version10,
            salt: vec![0; 16],
            parallelism: 8,
            memory: 1024,
            iterations: 4,
        })
        .expect("Creating a new outer header");
        header.custom_data = Some(VariantList::new());

        let result = serialize(&header);

        let mut expected = Vec::new();
        expected.extend_from_slice(&hex!("02   10 00 00 00"));
        expected.append(&mut serialize(&header.cipher));

        expected.extend_from_slice(&hex!("03   04 00 00 00"));
        expected.append(&mut serialize(&header.compression));

        expected.extend_from_slice(&hex!("04"));
        expected.extend_from_slice(&(header.main_seed.len() as u32).to_le_bytes());
        expected.append(&mut header.main_seed);

        expected.extend_from_slice(&hex!("07"));
        expected.extend_from_slice(&(header.iv.len() as u32).to_le_bytes());
        expected.append(&mut header.iv);

        {
            let mut parameter = serialize(&VariantList::from(&header.kdf_parameters));
            expected.extend_from_slice(&hex!("0b"));
            expected.extend_from_slice(&(parameter.len() as u32).to_le_bytes());
            expected.append(&mut parameter);
        }

        expected.extend_from_slice(&hex!("0c   03 00 00 00   00 01    00"));
        expected.extend_from_slice(&hex!("00   04 00 00 00   0d 0a 0d 0a"));

        assert_eq!(result, expected);
    }

    #[test]
    fn test_inner_reset() {
        let mut header = InnerHeader {
            cipher: StreamCipher::Salsa20,
            key: vec![0; 16],
            binaries: Vec::new(),
        };

        header.reset_cipher().expect("Resetting cipher");

        assert_eq!(header.cipher, StreamCipher::ChaCha20);
        assert_ne!(header.key, vec![0; 16]);
    }

    #[test]
    fn test_inner_deserialize() {
        fn deserialize<T: AsRef<[u8]>>(data: T) -> Result<InnerHeader, Error> {
            let mut cursor = Cursor::new(data);
            InnerHeader::deserialize(&mut cursor)
        }

        assert!(matches!(
            deserialize(hex!("88")).expect_err("Deserializing invalid field type"),
            Error::UnsupportedHeaderFieldType(0x88)
        ));

        assert!(matches!(
            deserialize(hex!("01   02 00 00 00"))
                .expect_err("Deserializing invalid cipher field size"),
            Error::InvalidFieldSize
        ));

        assert!(matches!(
            deserialize(hex!("01   04 00 00 00   03 00 00 00"))
                .expect_err("Deserializing without end of header"),
            Error::Io(_)
        ));

        assert!(matches!(
            deserialize(hex!("01   04 00 00 00   03 00 00 00   00    00 00 00 00"))
                .expect_err("Deserializing with fields missing"),
            Error::HeaderFieldsMissing
        ));

        let header = deserialize(hex!(
            "
            01   04 00 00 00   03 00 00 00
            02   08 00 00 00   01 02 03 04 05 06 07 08
            03   01 00 00 00   00
            03   05 00 00 00   01 02 03 04 05
            00   00 00 00 00
        "
        ))
        .expect("Deserializing a complete inner header");

        assert_eq!(header.cipher, StreamCipher::ChaCha20);
        assert_eq!(header.key, hex!("01 02 03 04 05 06 07 08"));
        assert_eq!(header.binaries.len(), 2);
        assert_eq!(
            header.binaries[0],
            Binary {
                flags: 0x00,
                data: hex!("").to_vec(),
            }
        );
        assert_eq!(
            header.binaries[1],
            Binary {
                flags: 0x01,
                data: hex!("02 03 04 05").to_vec(),
            }
        );
    }

    #[test]
    fn test_inner_serialize() {
        let header = InnerHeader {
            cipher: StreamCipher::ChaCha20,
            key: hex!("01 02 03 04 05 06 07 08").to_vec(),
            binaries: vec![
                Binary {
                    flags: 0x00,
                    data: hex!("").to_vec(),
                },
                Binary {
                    flags: 0x01,
                    data: hex!("02 03 04 05").to_vec(),
                },
            ],
        };

        assert_eq!(
            serialize(&header),
            hex!(
                "
                01   04 00 00 00   03 00 00 00
                02   08 00 00 00   01 02 03 04 05 06 07 08
                03   01 00 00 00   00
                03   05 00 00 00   01 02 03 04 05
                00   00 00 00 00
            "
            )
        );
    }
}
