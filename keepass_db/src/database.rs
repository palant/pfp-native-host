use hmac::Mac;
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::io::{Read, Write};

use crate::io::{Deserialize, DeserializeWithSize, Serialize};
use crate::{
    Compression, DatabaseVersion, DatabaseXML, Error, HmacBlockStreamReader, HmacBlockStreamWriter,
    KdfParameters, Keys, OuterHeader,
};

struct ReadRecorder<R> {
    pub inner: R,
    pub data: Vec<u8>,
}

impl<R: Read> ReadRecorder<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            data: Vec::new(),
        }
    }
}

impl<R: Read> Read for ReadRecorder<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let size = self.inner.read(buf)?;
        self.data.extend_from_slice(&buf[0..size]);
        Ok(size)
    }
}

struct WriteRecorder<W> {
    pub inner: W,
    pub data: Vec<u8>,
}

impl<W: Write> WriteRecorder<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            data: Vec::new(),
        }
    }
}

impl<W: Write> Write for WriteRecorder<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let size = self.inner.write(buf)?;
        self.data.extend_from_slice(&buf[0..size]);
        Ok(size)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

pub struct Database {
    version: DatabaseVersion,
    header: OuterHeader,
    header_data: Cell<Vec<u8>>,
    header_hmac: Vec<u8>,
}

impl Database {
    fn get_header_hmac(&self, keys: &Keys) -> Vec<u8> {
        let mut hasher = keys.get_hmac_hasher(-1);
        hasher.update(&self.header_data.take());
        hasher.finalize().into_bytes().to_vec()
    }

    pub fn unlock(&self, main_password: &str) -> Result<Keys, Error> {
        let keys = Keys::derive(main_password, &self.header)?;
        if self.get_header_hmac(&keys) != self.header_hmac {
            return Err(Error::InvalidCredentials);
        }
        Ok(keys)
    }

    pub fn decrypt<R: Read>(&self, input: &mut R, keys: &Keys) -> Result<DatabaseXML, Error> {
        let mut hmac_reader = HmacBlockStreamReader::new(input, keys);

        // TODO: Do this in a "streamed" fashion
        let mut data = Vec::new();
        hmac_reader.read_to_end(&mut data)?;
        self.header
            .cipher
            .decrypt(&mut data, &keys.encryption, &self.header.iv)?;

        if let Compression::Gzip = self.header.compression {
            let cursor = std::io::Cursor::new(data);
            let mut decoder = libflate::gzip::Decoder::new(cursor)?;
            data = Vec::new();
            decoder.read_to_end(&mut data)?;
        }

        let mut cursor = std::io::Cursor::new(&data);
        DatabaseXML::new(&mut cursor)
    }

    pub fn save<W: Write>(
        &mut self,
        output: &mut W,
        keys: &Keys,
        xml: &mut DatabaseXML,
    ) -> Result<(), Error> {
        self.header.reset_iv()?;
        self.serialize(output)?;
        self.get_header_hmac(keys).serialize(output)?;

        let mut inner_data = Vec::new();
        xml.save(&mut inner_data)?;

        if let Compression::Gzip = self.header.compression {
            let mut encoder = libflate::gzip::Encoder::new(Vec::new())?;
            encoder.write_all(&inner_data)?;
            inner_data = encoder.finish().into_result()?;
        }

        self.header
            .cipher
            .encrypt(&mut inner_data, &keys.encryption, &self.header.iv)?;

        let mut hmac_writer = HmacBlockStreamWriter::new(output, keys);
        inner_data.serialize(&mut hmac_writer)?;
        hmac_writer.finish()?;

        Ok(())
    }

    pub fn get_kdf_parameters(&self) -> &KdfParameters {
        &self.header.kdf_parameters
    }
}

impl std::fmt::Debug for Database {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("Database")
            .field("version", &self.version)
            .field("header", &self.header)
            .field("header_hmac", &self.header_hmac)
            .finish()
    }
}

impl Serialize for Database {
    fn serialize<W: Write>(&self, output: &mut W) -> Result<(), Error> {
        let mut recorder = WriteRecorder::new(output);

        self.version.serialize(&mut recorder)?;
        self.header.serialize(&mut recorder)?;

        let header_data = recorder.data;

        {
            let mut hasher = Sha256::new();
            hasher.update(&header_data);
            hasher.finalize().as_slice().serialize(recorder.inner)?;
        }

        self.header_data.set(header_data);

        Ok(())
    }
}

impl Deserialize for Database {
    fn deserialize<R: Read>(input: &mut R) -> Result<Self, Error> {
        let mut recorder = ReadRecorder::new(input);

        let version = DatabaseVersion::deserialize(&mut recorder)?;
        let header = OuterHeader::deserialize(&mut recorder)?;

        let header_data = recorder.data;

        let header_hash = Vec::deserialize(recorder.inner, 32)?;
        let header_hmac = Vec::deserialize(recorder.inner, 32)?;

        {
            let mut hasher = Sha256::new();
            hasher.update(&header_data);

            if hasher.finalize().as_slice() != header_hash {
                return Err(Error::HeaderChecksumMismatch);
            }
        }

        Ok(Self {
            version,
            header,
            header_data: Cell::new(header_data),
            header_hmac,
        })
    }
}
