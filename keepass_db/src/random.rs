use crate::error::Error;

pub fn random_vec(size: usize) -> Result<Vec<u8>, Error> {
    let mut vec = Vec::with_capacity(size);
    vec.resize(size, 0);
    getrandom::getrandom(&mut vec).or(Err(Error::RandomNumberGeneratorFailed))?;
    Ok(vec)
}
