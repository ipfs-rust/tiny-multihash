use crate::error::Error;
use core::fmt::Debug;

/// Trait for a multihash digest.
pub trait MultihashDigest: Clone + Debug + Eq + Send + Sync + 'static {
    //const CODE: u64;

    /// Returns the code of the multihash.
    fn code(&self) -> u64;

    /// Returns the size of the digest.
    fn size(&self) -> u8;

    /// Returns the digest.
    fn digest(&self) -> &[u8];

    ///// Returns the hash of the input.
    fn new(code: u64, input: &[u8]) -> Result<Self, Error>;

    /// Reads a multihash from a byte stream.
    #[cfg(feature = "std")]
    fn read<R: std::io::Read>(r: R) -> Result<Self, Error>
    where
        Self: Sized;

    /// Parses a multihash from a bytes.
    #[cfg(feature = "std")]
    fn from_bytes(mut bytes: &[u8]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        Self::read(&mut bytes)
    }

    /// Writes a multihash to a byte stream.
    #[cfg(feature = "std")]
    fn write<W: std::io::Write>(&self, w: W) -> Result<(), Error> {
        write_mh(w, self)
    }

    /// Returns the bytes of a multihash.
    #[cfg(feature = "std")]
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        self.write(&mut bytes)
            .expect("writing to a vec should never fail");
        bytes
    }
}

/// Writes the multihash to a byte stream.
#[cfg(feature = "std")]
pub fn write_mh<W, D>(mut w: W, mh: &D) -> Result<(), Error>
where
    W: std::io::Write,
    D: MultihashDigest,
{
    use unsigned_varint::encode as varint_encode;

    let mut code_buf = varint_encode::u64_buffer();
    let code = varint_encode::u64(mh.code().into(), &mut code_buf);

    let mut size_buf = varint_encode::u8_buffer();
    let size = varint_encode::u8(mh.size(), &mut size_buf);

    w.write_all(code)?;
    w.write_all(size)?;
    w.write_all(mh.digest())?;
    Ok(())
}

/// Reads a code from a byte stream.
#[cfg(feature = "std")]
pub fn read_code<R>(mut r: R) -> Result<u64, Error>
where
    R: std::io::Read,
{
    use unsigned_varint::io::read_u64;
    Ok(read_u64(&mut r)?)
}

/// Reads a multihash from a byte stream.
#[cfg(feature = "std")]
pub fn read_digest<R, S, D>(mut r: R) -> Result<D, Error>
where
    R: std::io::Read,
    S: crate::hasher::Size,
    D: crate::hasher::Digest<S>,
{
    use generic_array::GenericArray;
    use unsigned_varint::io::read_u64;

    let size = read_u64(&mut r)?;
    if size != S::to_u64() {
        return Err(Error::InvalidSize(size));
    }
    let mut digest = GenericArray::default();
    r.read_exact(&mut digest)?;
    Ok(D::from(digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code::Multihash;
    use crate::hasher::Hasher;
    use crate::hasher_impl::strobe::Strobe256;

    #[test]
    fn roundtrip() {
        let digest = Strobe256::digest(b"hello world");
        let hash = Multihash::from(digest);
        let mut buf = [0u8; 35];
        hash.write(&mut buf[..]).unwrap();
        let hash2 = Multihash::read(&buf[..]).unwrap();
        assert_eq!(hash, hash2);
    }
}
