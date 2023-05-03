use std::io::{Read, Write};

use crate::io::{Deserialize, Serialize};
use crate::numeric_enum;
use crate::Error;

const UUID_AES256: [u8; 16] = hex_literal::hex!("31c1f2e6 bf71 4350 be58 05216afc5aff");
const UUID_TWOFISH: [u8; 16] = hex_literal::hex!("ad68f29f 576f 4bb9 a36a d47af965346c");
const UUID_CHACHA20: [u8; 16] = hex_literal::hex!("d6038a2b 8b6f 4cb5 a524 339a31dbb59a");

const AES_BLOCK_SIZE: usize = 16;
const TWOFISH_BLOCK_SIZE: usize = 16;

#[derive(Debug, Default, PartialEq)]
pub(crate) enum BlockCipher {
    Aes256,
    Twofish,
    #[default]
    ChaCha20,
}

impl BlockCipher {
    pub const SIZE: usize = UUID_AES256.len();

    pub fn iv_size(&self) -> usize {
        match self {
            Self::Aes256 => 16,
            Self::Twofish => 16,
            Self::ChaCha20 => 12,
        }
    }

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
    StreamCipher as u32 with error UnsupportedStreamCipher
    {
        Salsa20 = 2,
        #[default]
        ChaCha20 = 3,
    }
}

impl StreamCipher {
    pub fn key_size(&self) -> usize {
        match self {
            Self::Salsa20 => 32,
            Self::ChaCha20 => 64,
        }
    }

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
