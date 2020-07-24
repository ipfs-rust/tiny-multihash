//! Default Code and Multihash implementation.
use crate::hasher::Hasher;
use crate::multihash::MultihashDigest;
use multihash_proc_macro::Multihash;

#[derive(Clone, Debug, Eq, Multihash, PartialEq)]
pub enum Multihash {
    /// Multihash array for hash function.
    #[mh(code = 0x00, hasher = crate::Identity256)]
    Identity256(crate::IdentityDigest<crate::U32>),
    /// Multihash array for hash function.
    #[mh(code = 0x11, hasher = crate::Sha1)]
    Sha1(crate::Sha1Digest<crate::U20>),
    /// Multihash array for hash function.
    #[mh(code = 0x12, hasher = crate::Sha2_256)]
    Sha2_256(crate::Sha2Digest<crate::U32>),
    /// Multihash array for hash function.
    #[mh(code = 0x13, hasher = crate::Sha2_512)]
    Sha2_512(crate::Sha2Digest<crate::U64>),
    /// Multihash array for hash function.
    #[mh(code = 0x17, hasher = crate::Sha3_224)]
    Sha3_224(crate::Sha3Digest<crate::U28>),
    /// Multihash array for hash function.
    #[mh(code = 0x16, hasher = crate::Sha3_256)]
    Sha3_256(crate::Sha3Digest<crate::U32>),
    /// Multihash array for hash function.
    #[mh(code = 0x15, hasher = crate::Sha3_384)]
    Sha3_384(crate::Sha3Digest<crate::U48>),
    /// Multihash array for hash function.
    #[mh(code = 0x14, hasher = crate::Sha3_512)]
    Sha3_512(crate::Sha3Digest<crate::U64>),
    /// Multihash array for hash function.
    #[mh(code = 0x1a, hasher = crate::Keccak224)]
    Keccak224(crate::KeccakDigest<crate::U28>),
    /// Multihash array for hash function.
    #[mh(code = 0x1b, hasher = crate::Keccak256)]
    Keccak256(crate::KeccakDigest<crate::U32>),
    /// Multihash array for hash function.
    #[mh(code = 0x1c, hasher = crate::Keccak384)]
    Keccak384(crate::KeccakDigest<crate::U48>),
    /// Multihash array for hash function.
    #[mh(code = 0x1d, hasher = crate::Keccak512)]
    Keccak512(crate::KeccakDigest<crate::U64>),
    /// Multihash array for hash function.
    #[mh(code = 0xb220, hasher = crate::Blake2b256)]
    Blake2b256(crate::Blake2bDigest<crate::U32>),
    /// Multihash array for hash function.
    #[mh(code = 0xb240, hasher = crate::Blake2b512)]
    Blake2b512(crate::Blake2bDigest<crate::U64>),
    /// Multihash array for hash function.
    #[mh(code = 0xb250, hasher = crate::Blake2s128)]
    Blake2s128(crate::Blake2sDigest<crate::U16>),
    /// Multihash array for hash function.
    #[mh(code = 0xb260, hasher = crate::Blake2s256)]
    Blake2s256(crate::Blake2sDigest<crate::U32>),
    /// Multihash array for hash function.
    #[mh(code = 0xa0, hasher = crate::Strobe256)]
    Strobe256(crate::StrobeDigest<crate::U32>),
    /// Multihash array for hash function.
    #[mh(code = 0xa1, hasher = crate::Strobe512)]
    Strobe512(crate::StrobeDigest<crate::U64>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::Hasher;
    use crate::hasher_impl::strobe::{Strobe256, Strobe512};
    use crate::multihash::MultihashDigest;

    const STROBE_256: u64 = 0xa0;
    const STROBE_512: u64 = 0xa1;

    #[test]
    fn test_hasher_256() {
        let digest = Strobe256::digest(b"hello world");
        let hash = Multihash::from(digest.clone());
        let hash2 = Multihash::new(STROBE_256, b"hello world").unwrap();
        assert_eq!(hash.code(), STROBE_256);
        assert_eq!(hash.size(), 32);
        assert_eq!(hash.digest(), digest.as_ref());
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_hasher_512() {
        let digest = Strobe512::digest(b"hello world");
        let hash = Multihash::from(digest.clone());
        let hash2 = Multihash::new(STROBE_512, b"hello world").unwrap();
        assert_eq!(hash.code(), STROBE_512);
        assert_eq!(hash.size(), 64);
        assert_eq!(hash.digest(), digest.as_ref());
        assert_eq!(hash, hash2);
    }
}
