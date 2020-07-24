use multihash::{read_code, read_digest, Error, Hasher, Multihash, MultihashDigest};

#[derive(Clone, Debug, Eq, Multihash, PartialEq)]
pub enum Multihash {
    #[mh(code = 0x01, hasher = multihash::Sha2_256)]
    Foo(multihash::Sha2Digest<multihash::U32>),
    #[mh(code = 0x02, hasher = multihash::Sha2_512)]
    Bar(multihash::Sha2Digest<multihash::U64>),
}
