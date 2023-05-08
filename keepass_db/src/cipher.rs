use std::io::{Read, Write};

use crate::io::{Deserialize, Serialize};
use crate::numeric_enum;
use crate::Error;

const UUID_AES256: [u8; 16] = hex_literal::hex!("31c1f2e6 bf71 4350 be58 05216afc5aff");
const UUID_TWOFISH: [u8; 16] = hex_literal::hex!("ad68f29f 576f 4bb9 a36a d47af965346c");
const UUID_CHACHA20: [u8; 16] = hex_literal::hex!("d6038a2b 8b6f 4cb5 a524 339a31dbb59a");

const AES_BLOCK_SIZE: usize = 16;
const TWOFISH_BLOCK_SIZE: usize = 16;

/// The KeePass database encryption approach as specified in the outer header.
#[derive(Debug, Default, PartialEq)]
pub(crate) enum BlockCipher {
    /// AES256-CBC with PKCS7 padding
    Aes256,
    /// Twofish-CBC with PKCS7 padding
    Twofish,
    #[default]
    /// ChaCha20 algorithm
    ChaCha20,
}

impl BlockCipher {
    /// Size of the outer header field value
    pub const SIZE: usize = UUID_AES256.len();

    /// Returns the size of the initialization vector for the selected algorithm
    pub fn iv_size(&self) -> usize {
        match self {
            Self::Aes256 => 16,
            Self::Twofish => 16,
            Self::ChaCha20 => 12,
        }
    }

    /// Decrypts a block of data in place with the selected algorithm, key and
    /// initialization vector. Might result in Error::DecryptionError.
    pub fn decrypt(&self, data: &mut Vec<u8>, key: &[u8], iv: &[u8]) -> Result<(), Error> {
        match self {
            Self::Aes256 => {
                use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
                let decryptor = cbc::Decryptor::<aes::Aes256>::new(key.into(), iv.into());
                let len = decryptor
                    .decrypt_padded_mut::<Pkcs7>(data)
                    .or(Err(Error::DecryptionError))?
                    .len();
                data.truncate(len);
            }
            Self::Twofish => {
                use twofish::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
                let decryptor = cbc::Decryptor::<twofish::Twofish>::new(key.into(), iv.into());
                let len = decryptor
                    .decrypt_padded_mut::<Pkcs7>(data)
                    .or(Err(Error::DecryptionError))?
                    .len();
                data.truncate(len);
            }
            Self::ChaCha20 => {
                use chacha20::cipher::{KeyIvInit, StreamCipher};
                let mut cipher = chacha20::ChaCha20::new(key.into(), iv.into());
                cipher.apply_keystream(data);
            }
        };
        Ok(())
    }

    /// Encrypts a block of data in place with the selected algorithm, key and
    /// initialization vector. Might result in Error::EncryptionError.
    pub fn encrypt(&self, data: &mut Vec<u8>, key: &[u8], iv: &[u8]) -> Result<(), Error> {
        match self {
            Self::Aes256 => {
                use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
                let encryptor = cbc::Encryptor::<aes::Aes256>::new(key.into(), iv.into());
                let msg_size = data.len();
                data.resize(data.len() + AES_BLOCK_SIZE, 0);
                let len = encryptor
                    .encrypt_padded_mut::<Pkcs7>(data, msg_size)
                    .or(Err(Error::EncryptionError))?
                    .len();
                data.truncate(len);
            }
            Self::Twofish => {
                use twofish::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
                let encryptor = cbc::Encryptor::<twofish::Twofish>::new(key.into(), iv.into());
                let msg_size = data.len();
                data.resize(data.len() + TWOFISH_BLOCK_SIZE, 0);
                let len = encryptor
                    .encrypt_padded_mut::<Pkcs7>(data, msg_size)
                    .or(Err(Error::EncryptionError))?
                    .len();
                data.truncate(len);
            }
            Self::ChaCha20 => {
                use chacha20::cipher::{KeyIvInit, StreamCipher};
                let mut cipher = chacha20::ChaCha20::new(key.into(), iv.into());
                cipher.apply_keystream(data);
            }
        };
        Ok(())
    }
}

impl Serialize for BlockCipher {
    fn serialize<W: Write>(&self, output: &mut W) -> Result<(), Error> {
        match self {
            Self::Aes256 => UUID_AES256,
            Self::Twofish => UUID_TWOFISH,
            Self::ChaCha20 => UUID_CHACHA20,
        }
        .serialize(output)
    }
}

impl Deserialize for BlockCipher {
    fn deserialize<R: Read>(input: &mut R) -> Result<Self, Error> {
        let mut buffer = [0u8; Self::SIZE];
        input.read_exact(&mut buffer)?;
        Ok(match buffer {
            UUID_AES256 => Self::Aes256,
            UUID_TWOFISH => Self::Twofish,
            UUID_CHACHA20 => Self::ChaCha20,
            _ => return Err(Error::UnsupportedBlockCipher),
        })
    }
}

numeric_enum! {
    #[derive(Default)]
    /// The stream cipher used for protected fields as specified in the inner header
    /// of the KeePass database.
    StreamCipher as u32 with error UnsupportedStreamCipher
    {
        /// Salsa20 algorithm with constant nonce (not expected to be used in
        /// KeePass 4 databases)
        Salsa20 = 2,
        #[default]
        /// ChaCha20 algorithm with both key and nonce derived from the
        /// supplied "key"
        ChaCha20 = 3,
    }
}

impl StreamCipher {
    /// The expected "key" size for the selected algorithm.
    pub fn key_size(&self) -> usize {
        match self {
            Self::Salsa20 => 32,
            Self::ChaCha20 => 64,
        }
    }

    /// Creates a `cipher::StreamCipher` instance for the selected algorithm
    /// and given "key". For Salsa20, a constant nonce will be used. For
    /// ChaCha20, the supplied "key" is hashed and part of the result used as
    /// key, another part as nonce.
    pub fn create(&self, key: &[u8]) -> Box<dyn cipher::StreamCipher> {
        match self {
            Self::Salsa20 => {
                use salsa20::cipher::KeyIvInit;
                Box::new(salsa20::Salsa20::new(
                    key.into(),
                    &hex_literal::hex!("e830094b97205d2a").into(),
                ))
            }
            Self::ChaCha20 => {
                let hash = {
                    use sha2::{Digest, Sha512};
                    let mut hasher = Sha512::new();
                    hasher.update(key);
                    hasher.finalize()
                };

                use chacha20::cipher::KeyIvInit;
                Box::new(chacha20::ChaCha20::new(
                    hash[0..32].into(),
                    hash[32..44].into(),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use std::io::Cursor;

    fn serialize<S: Serialize>(data: S) -> Vec<u8> {
        let mut result = Vec::new();
        data.serialize(&mut result).unwrap();
        result
    }

    #[test]
    pub fn test_block_deserialize() {
        fn deserialize<const SIZE: usize>(data: [u8; SIZE]) -> Result<BlockCipher, Error> {
            let mut cursor = Cursor::new(data);
            BlockCipher::deserialize(&mut cursor)
        }

        assert!(matches!(
            deserialize(hex!("")).expect_err("Deserializing empty data"),
            Error::Io(_)
        ));

        assert!(matches!(
            deserialize(hex!("61ab05a1 9464 41c3 8d74 3a563df8dd35"))
                .expect_err("Deserializing AES-128 cipher"),
            Error::UnsupportedBlockCipher
        ));

        assert_eq!(
            deserialize(hex!("31c1f2e6 bf71 4350 be58 05216afc5aff"))
                .expect("Deserializing AES-256 cipher"),
            BlockCipher::Aes256
        );
    }

    #[test]
    pub fn test_block_serialize() {
        assert_eq!(
            serialize(BlockCipher::Aes256),
            hex!("31c1f2e6 bf71 4350 be58 05216afc5aff")
        );
    }

    #[test]
    pub fn test_block_size() {
        assert_eq!(BlockCipher::SIZE, 16);

        assert_eq!(BlockCipher::Aes256.iv_size(), 16);
        assert_eq!(BlockCipher::Twofish.iv_size(), 16);
        assert_eq!(BlockCipher::ChaCha20.iv_size(), 12);
    }

    #[test]
    pub fn test_block_encrypt_decrypt() {
        let mut data = b"test".to_vec();
        BlockCipher::Aes256
            .encrypt(
                &mut data,
                b"01234567012345670123456701234567",
                b"abcdefghabcdefgh",
            )
            .unwrap();
        assert_eq!(data, hex!("6301DF0B911C8E1E665C4AF9F3AE8271"));

        BlockCipher::Aes256
            .decrypt(
                &mut data,
                b"01234567012345670123456701234567",
                b"abcdefghabcdefgh",
            )
            .unwrap();
        assert_eq!(data, b"test");

        BlockCipher::ChaCha20
            .encrypt(
                &mut data,
                b"01234567012345670123456701234567",
                b"abcdefghabcd",
            )
            .unwrap();
        assert_eq!(data, hex!("A1CFF2F2"));

        BlockCipher::ChaCha20
            .decrypt(
                &mut data,
                b"01234567012345670123456701234567",
                b"abcdefghabcd",
            )
            .unwrap();
        assert_eq!(data, b"test");
    }

    #[test]
    pub fn test_stream_deserialize() {
        fn deserialize<const SIZE: usize>(data: [u8; SIZE]) -> Result<StreamCipher, Error> {
            let mut cursor = Cursor::new(data);
            StreamCipher::deserialize(&mut cursor)
        }

        assert!(matches!(
            deserialize(hex!("")).expect_err("Deserializing empty data"),
            Error::Io(_)
        ));

        assert!(matches!(
            deserialize(hex!("01 00 00 00")).expect_err("Deserializing ArcFourVariant cipher"),
            Error::UnsupportedStreamCipher(1)
        ));

        assert_eq!(
            deserialize(hex!("03 00 00 00")).expect("Deserializing ChaCha20 cipher"),
            StreamCipher::ChaCha20
        );
    }

    #[test]
    pub fn test_stream_serialize() {
        assert_eq!(serialize(StreamCipher::ChaCha20), hex!("03 00 00 00"));
    }

    #[test]
    pub fn test_stream_size() {
        assert_eq!(StreamCipher::Salsa20.key_size(), 32);
        assert_eq!(StreamCipher::ChaCha20.key_size(), 64);
    }

    #[test]
    pub fn test_stream_encrypt_decrypt() {
        let mut data = b"test".to_vec();

        let mut cipher = StreamCipher::Salsa20.create(b"z1234567012345670123456701234567");
        cipher.apply_keystream(&mut data);
        assert_eq!(data, hex!("F30E8D2E"));

        let mut cipher = StreamCipher::Salsa20.create(b"z1234567012345670123456701234567");
        cipher.apply_keystream(&mut data);
        assert_eq!(data, b"test");

        let mut cipher = StreamCipher::ChaCha20.create(b"key");
        cipher.apply_keystream(&mut data);
        assert_eq!(data, hex!("244CFC4D"));

        let mut cipher = StreamCipher::ChaCha20.create(b"key");
        cipher.apply_keystream(&mut data);
        assert_eq!(data, b"test");
    }
}
