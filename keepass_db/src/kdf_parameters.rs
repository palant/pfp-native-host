use crate::io::{Deserialize, DeserializeWithSize, Serialize};
use crate::{Error, VariantList, VariantValue};
use std::io::{Read, Write};

const UUID_ARGON2D: &[u8] = &hex_literal::hex!("ef636ddf 8c29 444b 91f7 a9a403e30a0c");
const UUID_ARGON2ID: &[u8] = &hex_literal::hex!("9e298b19 56db 4773 b23d fc3ec6f0a1e6");
const UUID_AESKDF: &[u8] = &hex_literal::hex!("7c02bb8279a7 4ac0 927d 114a00648238");

const SALT_SIZE: usize = 16;

#[derive(Clone, Debug)]
pub struct KdfParameters {
    pub algorithm: argon2::Variant,
    pub salt: Vec<u8>,
    pub version: argon2::Version,
    pub parallelism: u32,
    pub memory: u32,
    pub iterations: u32,
}

impl KdfParameters {
    pub fn generate(memory: u32, parallelism: u32, seconds: f32) -> Result<Self, Error> {
        // KeePass recommends Argon2d over Argon2id, use this
        let algorithm = argon2::Variant::D;
        let version = argon2::Version::Version13;
        let size = 32;

        let salt = vec![0; SALT_SIZE];
        let mut buffer = vec![0; size];

        let start = std::time::Instant::now();
        argon2::hash(
            1,
            memory,
            parallelism,
            Some(b"dummy"),
            Some(&salt),
            Some(&mut buffer),
            None,
            algorithm,
            version,
        ).map_err(|_| Error::KeyDerivation)?;
        let duration = start.elapsed();
        let iterations = (seconds / duration.as_secs_f32()).ceil().max(1.0) as u32;

        Ok(Self {
            algorithm,
            salt: crate::random::random_vec(SALT_SIZE)?,
            version,
            parallelism,
            memory,
            iterations,
        })
    }

    pub fn reset_salt(&mut self) -> Result<(), Error> {
        self.salt = crate::random::random_vec(SALT_SIZE)?;
        Ok(())
    }

    pub fn derive_key(&self, password: &[u8], size: usize) -> Result<Vec<u8>, Error> {
        let mut buffer = vec![0; size];
        argon2::hash(
            self.iterations,
            self.memory,
            self.parallelism,
            Some(password),
            Some(&self.salt),
            Some(&mut buffer),
            None,
            self.algorithm,
            self.version,
        ).map_err(|_| Error::KeyDerivation)?;
        Ok(buffer)
    }
}

impl From<&KdfParameters> for VariantList {
    fn from(value: &KdfParameters) -> Self {
        let mut list = VariantList::new();
        match value.algorithm {
            argon2::Variant::D => {
                list.add("$UUID", VariantValue::Bytes(UUID_ARGON2D.to_vec()))
            }
            argon2::Variant::ID => {
                list.add("$UUID", VariantValue::Bytes(UUID_ARGON2ID.to_vec()))
            }
            _ => panic!("Unexpected KDF algorithm configured"),
        };
        list.add("S", VariantValue::Bytes(value.salt.clone()));
        list.add("V", VariantValue::U32(value.version.to_int()));
        list.add("P", VariantValue::U32(value.parallelism));
        list.add("M", VariantValue::U64(value.memory as u64 * 1024));
        list.add("I", VariantValue::U64(value.iterations as u64));
        list
    }
}

impl TryFrom<VariantList> for KdfParameters {
    type Error = Error;
    fn try_from(list: VariantList) -> Result<Self, Self::Error> {
        macro_rules! get_field {
            ($type: ident, $key: literal) => {
                if let Some(VariantValue::$type(value)) = list.get($key) {
                    value
                } else {
                    return Err(Error::KdfFieldMissingOrInvalid($key));
                }
            };
        }

        let algorithm = match get_field!(Bytes, "$UUID").as_slice() {
            UUID_ARGON2D => argon2::Variant::D,
            UUID_ARGON2ID => argon2::Variant::ID,
            UUID_AESKDF => return Err(Error::AesKDFUnsupported),
            _ => return Err(Error::UnsupportedKDF),
        };
        let salt = get_field!(Bytes, "S");
        let version = argon2::Version::from_int(get_field!(U32, "V"))
            .ok_or(Error::UnsupportedKDF)?;
        let parallelism = get_field!(U32, "P");
        let memory = (get_field!(U64, "M") / 1024)
            .try_into()
            .map_err(|_| Error::KDFParameterExceedsRange)?;
        let iterations = get_field!(U64, "I")
            .try_into()
            .map_err(|_| Error::KDFParameterExceedsRange)?;

        Ok(Self {
            algorithm,
            salt,
            version,
            parallelism,
            memory,
            iterations,
        })
    }
}

impl Serialize for KdfParameters {
    fn serialize<W: Write>(&self, output: &mut W) -> Result<(), Error> {
        use bitstream_io::{BigEndian, BitWrite, BitWriter};

        let mut bits = BitWriter::endian(output, BigEndian);
        bits.write(
            2,
            match self.algorithm {
                argon2::Variant::D => 0,
                argon2::Variant::I => 1,
                argon2::Variant::ID => 2,
            },
        )?;
        bits.write(
            1,
            match self.version {
                argon2::Version::Version10 => 0,
                argon2::Version::Version13 => 1,
            },
        )?;

        let bit_count = u32::BITS - self.parallelism.leading_zeros();
        bits.write(5, bit_count)?;
        bits.write(bit_count, self.parallelism)?;

        if self.memory & 0x3FF != 0 {
            return Err(Error::KDFParameterExceedsRange);
        }
        let memory = self.memory >> 10;
        let bit_count = u32::BITS - memory.leading_zeros();
        bits.write(5, bit_count)?;
        bits.write(bit_count, memory)?;

        let bit_count = u32::BITS - self.iterations.leading_zeros();
        bits.write(5, bit_count)?;
        bits.write(bit_count, self.iterations)?;

        if self.salt.len() != SALT_SIZE {
            return Err(Error::KDFParameterExceedsRange);
        }
        bits.byte_align()?;
        self.salt.serialize(bits.into_writer())?;
        Ok(())
    }
}

impl Deserialize for KdfParameters {
    fn deserialize<R: Read>(input: &mut R) -> Result<Self, Error> {
        use bitstream_io::{BigEndian, BitRead, BitReader};

        let mut bits = BitReader::endian(input, BigEndian);

        let algorithm = match bits.read(2)? {
            0 => argon2::Variant::D,
            1 => argon2::Variant::I,
            2 => argon2::Variant::ID,
            _ => return Err(Error::UnsupportedKDF),
        };

        let version = match bits.read(1)? {
            0 => argon2::Version::Version10,
            1 => argon2::Version::Version13,
            _ => return Err(Error::UnsupportedKDF),
        };

        let bit_count = bits.read(5)?;
        let parallelism = bits.read(bit_count)?;

        let bit_count = bits.read(5)?;
        let memory = bits.read::<u32>(bit_count)? << 10;

        let bit_count = bits.read(5)?;
        let iterations = bits.read(bit_count)?;

        bits.byte_align();
        let salt = Vec::deserialize(bits.into_reader(), SALT_SIZE)?;

        Ok(KdfParameters {
            algorithm,
            salt,
            version,
            parallelism,
            memory,
            iterations,
        })
    }
}
