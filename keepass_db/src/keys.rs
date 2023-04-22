use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

use crate::{Error, OuterHeader};

const KEY_SIZE: usize = 32;
const HMAC_SIZE: usize = 64;

#[derive(Debug)]
pub struct Keys {
    pub encryption: Vec<u8>,
    hmac: Vec<u8>,
}

impl Keys {
    pub fn derive(main_password: &str, header: &OuterHeader) -> Result<Self, Error> {
        let hashed_password = {
            let mut hasher = Sha256::new();
            hasher.update(main_password);
            hasher.finalize()
        };

        let composite_key = {
            let mut hasher = Sha256::new();
            hasher.update(hashed_password);
            // TODO: Optionally hash a key file here
            hasher.finalize().to_vec()
        };

        let derived_key = header.kdf_parameters.derive_key(&composite_key, KEY_SIZE)?;

        let encryption = {
            let mut hasher = Sha256::new();
            hasher.update(&header.main_seed);
            hasher.update(&derived_key);
            hasher.finalize().to_vec()
        };

        let hmac = {
            let mut hasher = Sha512::new();
            hasher.update(&header.main_seed);
            hasher.update(&derived_key);
            hasher.update([1]);
            hasher.finalize().to_vec()
        };

        Ok(Self { encryption, hmac })
    }

    pub fn get_hmac_hasher(&self, block_index: i64) -> Hmac<Sha256> {
        let key = {
            let mut hasher = Sha512::new();
            hasher.update(block_index.to_le_bytes());
            hasher.update(&self.hmac);
            hasher.finalize()
        };

        // An error can only happen here for a wrong key size. We know that the key size is correct, so calling .unwrap.
        Hmac::<Sha256>::new_from_slice(&key).unwrap()
    }

    pub fn to_string(&self) -> (String, String) {
        let encryption = base64::engine::general_purpose::STANDARD.encode(&self.encryption);
        let hmac = base64::engine::general_purpose::STANDARD.encode(&self.hmac);
        (encryption, hmac)
    }

    pub fn from_string(encryption: String, hmac: String) -> Result<Self, Error> {
        let encryption_decoded = base64::engine::general_purpose::STANDARD
            .decode(encryption)
            .or(Err(Error::InvalidCredentials))?;
        let hmac_decoded = base64::engine::general_purpose::STANDARD
            .decode(hmac)
            .or(Err(Error::InvalidCredentials))?;

        if encryption_decoded.len() != KEY_SIZE || hmac_decoded.len() != HMAC_SIZE {
            return Err(Error::InvalidCredentials);
        }

        Ok(Self {
            encryption: encryption_decoded,
            hmac: hmac_decoded,
        })
    }
}
