use crate::io::{Deserialize, DeserializeWithSize, Serialize};
use crate::{Error, VariantList, VariantValue};
use std::io::{Read, Write};

const UUID_ARGON2D: &[u8] = &hex_literal::hex!("ef636ddf 8c29 444b 91f7 a9a403e30a0c");
const UUID_ARGON2ID: &[u8] = &hex_literal::hex!("9e298b19 56db 4773 b23d fc3ec6f0a1e6");
const UUID_AESKDF: &[u8] = &hex_literal::hex!("7c02bb8279a7 4ac0 927d 114a00648238");

const SALT_SIZE: usize = 16;

#[derive(Clone, Debug)]
pub struct KdfParameters {
    pub algorithm: argon2::Algorithm,
    pub salt: Vec<u8>,
    pub version: argon2::Version,
    pub parallelism: u32,
    pub memory: u32,
    pub iterations: u32,
}

impl KdfParameters {
    pub fn reset_salt(&mut self) -> Result<(), Error> {
        let mut salt = Vec::new();
        salt.resize(SALT_SIZE, 0);
        getrandom::getrandom(&mut salt).or(Err(Error::RandomNumberGeneratorFailed))?;
        self.salt = salt;
        Ok(())
    }

    pub fn derive_key(&self, password: &[u8], size: usize) -> Result<Vec<u8>, Error> {
        let params =
            argon2::Params::new(self.memory, self.iterations, self.parallelism, Some(size))?;
        let hasher = argon2::Argon2::new(self.algorithm, self.version, params);

        let mut buffer = Vec::new();
        buffer.resize(size, 0);
        hasher.hash_password_into(password, &self.salt, &mut buffer)?;
        Ok(buffer)
    }
}

impl From<&KdfParameters> for VariantList {
    fn from(value: &KdfParameters) -> Self {
        let mut list = VariantList::new();
        match value.algorithm {
            argon2::Algorithm::Argon2d => {
                list.add("$UUID", VariantValue::Bytes(UUID_ARGON2D.to_vec()))
            }
            argon2::Algorithm::Argon2id => {
                list.add("$UUID", VariantValue::Bytes(UUID_ARGON2ID.to_vec()))
            }
            _ => panic!("Unexpected KDF algorithm configured"),
        };
        list.add("S", VariantValue::Bytes(value.salt.clone()));
        list.add("V", VariantValue::U32(value.version.into()));
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
            UUID_ARGON2D => argon2::Algorithm::Argon2d,
            UUID_ARGON2ID => argon2::Algorithm::Argon2id,
            UUID_AESKDF => return Err(Error::AesKDFUnsupported),
            _ => return Err(Error::UnsupportedKDF),
        };
        let salt = get_field!(Bytes, "S");
        let version = get_field!(U32, "V")
            .try_into()
            .map_err(|_| Error::UnsupportedKDF)?;
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
                argon2::Algorithm::Argon2d => 0,
                argon2::Algorithm::Argon2i => 1,
                argon2::Algorithm::Argon2id => 2,
            },
        )?;
        bits.write(
            1,
            match self.version {
                argon2::Version::V0x10 => 0,
                argon2::Version::V0x13 => 1,
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
            0 => argon2::Algorithm::Argon2d,
            1 => argon2::Algorithm::Argon2i,
            2 => argon2::Algorithm::Argon2id,
            _ => return Err(Error::UnsupportedKDF),
        };

        let version = match bits.read(1)? {
            0 => argon2::Version::V0x10,
            1 => argon2::Version::V0x13,
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
