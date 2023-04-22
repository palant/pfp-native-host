use hmac::Mac;
use std::io::{Read, Write};

use crate::io::{Deserialize, DeserializeWithSize, Serialize};
use crate::{Error, Keys};

const BLOCK_SIZE: usize = 1024 * 1024;

pub(crate) struct HmacBlockStreamReader<'a, R> {
    index: i64,
    current: Option<Vec<u8>>,
    pos: usize,
    inner: &'a mut R,
    keys: &'a Keys,
}

impl<'a, R: Read> HmacBlockStreamReader<'a, R> {
    pub fn new(inner: &'a mut R, keys: &'a Keys) -> Self {
        Self {
            index: -1,
            current: None,
            pos: 0,
            inner,
            keys,
        }
    }

    fn next_block(&mut self) -> Result<(), Error> {
        self.index += 1;

        let hash_expected = Vec::deserialize(self.inner, 32)?;
        let block_size = u32::deserialize(self.inner)?;
        let block = Vec::deserialize(self.inner, block_size as usize)?;

        let mut hasher = self.keys.get_hmac_hasher(self.index);
        hasher.update(&self.index.to_le_bytes());
        hasher.update(&block_size.to_le_bytes());
        hasher.update(&block);
        let hash = hasher.finalize().into_bytes();
        if hash.as_slice() != hash_expected {
            return Err(Error::CorruptDatabase);
        }

        if block_size != 0 {
            self.current = Some(block);
            self.pos = 0;
        }

        Ok(())
    }
}

impl<R: Read> Read for HmacBlockStreamReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.current.is_none() {
            self.next_block()?;
        }

        if let Some(block) = &self.current {
            let remaining = block.len() - self.pos;
            if buf.len() < remaining {
                buf.copy_from_slice(&block[self.pos..self.pos + buf.len()]);
                self.pos += buf.len();
                Ok(buf.len())
            } else {
                buf[0..remaining].copy_from_slice(&block[self.pos..]);
                self.current = None;
                Ok(remaining)
            }
        } else {
            Ok(0)
        }
    }
}

pub(crate) struct HmacBlockStreamWriter<'a, W> {
    index: i64,
    current: Vec<u8>,
    inner: &'a mut W,
    keys: &'a Keys,
}

impl<'a, W: Write> HmacBlockStreamWriter<'a, W> {
    pub fn new(inner: &'a mut W, keys: &'a Keys) -> Self {
        Self {
            index: 0,
            current: Vec::new(),
            inner,
            keys,
        }
    }

    fn write_block(&mut self) -> Result<(), Error> {
        let mut hasher = self.keys.get_hmac_hasher(self.index);
        hasher.update(&self.index.to_le_bytes());
        hasher.update(&(self.current.len() as u32).to_le_bytes());
        hasher.update(&self.current);
        hasher.finalize().into_bytes().serialize(self.inner)?;

        (self.current.len() as u32).serialize(self.inner)?;
        self.current.serialize(self.inner)?;

        self.index += 1;
        self.current = Vec::new();

        Ok(())
    }

    pub fn finish(&mut self) -> Result<(), Error> {
        if !self.current.is_empty() {
            self.write_block()?;
        }
        self.write_block()
    }
}

impl<W: Write> Write for HmacBlockStreamWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let remaining = BLOCK_SIZE - self.current.len();
        if buf.len() < remaining {
            self.current.extend_from_slice(buf);
            Ok(buf.len())
        } else {
            self.current.extend_from_slice(&buf[0..remaining]);
            self.write_block()?;
            Ok(remaining)
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.write_block()?;
        self.inner.flush()
    }
}
