use crate::error::Error;

pub fn random_vec(size: usize) -> Result<Vec<u8>, Error> {
    let mut vec = vec![0; size];
    getrandom::getrandom(&mut vec).or(Err(Error::RandomNumberGeneratorFailed))?;
    Ok(vec)
}
