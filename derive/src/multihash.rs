use std::collections::HashSet;

use crate::utils;
use proc_macro2::TokenStream;
use quote::quote;
#[cfg(not(test))]
use quote::ToTokens;
use syn::parse::{Parse, ParseStream};
use syn::spanned::Spanned;
use synstructure::{Structure, VariantInfo};

mod kw {
    use syn::custom_keyword;

    custom_keyword!(code);
    custom_keyword!(digest);
    custom_keyword!(hasher);
    custom_keyword!(mh);
    custom_keyword!(max_size);
    custom_keyword!(no_max_size_errors);
}

/// Attributes for the enum items.
#[derive(Debug)]
enum MhAttr {
    Code(utils::Attr<kw::code, syn::Expr>),
    Hasher(utils::Attr<kw::hasher, Box<syn::Type>>),
    Digest(utils::Attr<kw::digest, syn::Path>),
}

impl Parse for MhAttr {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        if input.peek(kw::code) {
            Ok(MhAttr::Code(input.parse()?))
        } else if input.peek(kw::hasher) {
            Ok(MhAttr::Hasher(input.parse()?))
        } else {
            Ok(MhAttr::Digest(input.parse()?))
        }
    }
}

/// Attributes of the top-level derive.
#[derive(Debug)]
enum DeriveAttr {
    MaxSize(utils::Attr<kw::max_size, syn::Type>),
    NoMaxSizeErrors(kw::no_max_size_errors),
}

impl Parse for DeriveAttr {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        if input.peek(kw::max_size) {
            Ok(Self::MaxSize(input.parse()?))
        } else if input.peek(kw::no_max_size_errors) {
            Ok(Self::NoMaxSizeErrors(input.parse()?))
        } else {
            Err(syn::Error::new(input.span(), "unknown attribute"))
        }
    }
}

struct Params {
    mh_crate: syn::Ident,
    code_enum: syn::Ident,
}

#[derive(Debug)]
struct Hash {
    ident: syn::Ident,
    code: syn::Expr,
    hasher: Box<syn::Type>,
    digest: syn::Path,
}

impl Hash {
    fn code_into_u64(&self, params: &Params) -> TokenStream {
        let ident = &self.ident;
        let code_enum = &params.code_enum;
        let code = &self.code;
        quote!(#code_enum::#ident => #code)
    }

    fn code_from_u64(&self) -> TokenStream {
        let ident = &self.ident;
        let code = &self.code;
        quote!(#code => Ok(Self::#ident))
    }

    fn code_digest(&self, params: &Params) -> TokenStream {
        let ident = &self.ident;
        let hasher = &self.hasher;
        let code = &self.code;
        let mh_crate = &params.mh_crate;
        quote!(Self::#ident => {
           let digest = #hasher::digest(input);
           #mh_crate::Multihash::wrap(#code, &digest.as_ref()).unwrap()
        })
    }

    fn from_digest(&self, params: &Params) -> TokenStream {
        let digest = &self.digest;
        let code_enum = &params.code_enum;
        let ident = &self.ident;
        quote! {
           impl From<&#digest> for #code_enum {
               fn from(digest: &#digest) -> Self {
                   Self::#ident
               }
           }
        }
    }
}

impl<'a> From<&'a VariantInfo<'a>> for Hash {
    fn from(bi: &'a VariantInfo<'a>) -> Self {
        let mut code = None;
        let mut digest = None;
        let mut hasher = None;
        for attr in bi.ast().attrs {
            let attr: Result<utils::Attrs<MhAttr>, _> = syn::parse2(attr.tokens.clone());
            if let Ok(attr) = attr {
                for attr in attr.attrs {
                    match attr {
                        MhAttr::Code(attr) => code = Some(attr.value),
                        MhAttr::Hasher(attr) => hasher = Some(attr.value),
                        MhAttr::Digest(attr) => digest = Some(attr.value),
                    }
                }
            }
        }

        let ident = bi.ast().ident.clone();
        let code = code.unwrap_or_else(|| {
            let msg = "Missing code attribute: e.g. #[mh(code = multihash::SHA3_256)]";
            #[cfg(test)]
            panic!(msg);
            #[cfg(not(test))]
            proc_macro_error::abort!(ident, msg);
        });
        let hasher = hasher.unwrap_or_else(|| {
            let msg = "Missing hasher attribute: e.g. #[mh(hasher = multihash::Sha2_256)]";
            #[cfg(test)]
            panic!(msg);
            #[cfg(not(test))]
            proc_macro_error::abort!(ident, msg);
        });
        let digest = digest.unwrap_or_else(|| {
            let msg = "Missing digest atttibute: e.g. #[mh(digest = multihash::Sha2Digest<U32>)]";
            #[cfg(test)]
            panic!(msg);
            #[cfg(not(test))]
            proc_macro_error::abort!(ident, msg);
        });
        Self {
            ident,
            code,
            digest,
            hasher,
        }
    }
}

/// Parse top-level enum [#mh()] attributes.
///
/// Returns the `max_size` and whether errors regarding to `max_size` should be reported or not.
fn parse_code_enum_attrs(ast: &syn::DeriveInput) -> (syn::Type, bool) {
    let mut max_size = None;
    let mut no_max_size_errors = false;

    for attr in &ast.attrs {
        let derive_attrs: Result<utils::Attrs<DeriveAttr>, _> = syn::parse2(attr.tokens.clone());
        if let Ok(derive_attrs) = derive_attrs {
            for derive_attr in derive_attrs.attrs {
                match derive_attr {
                    DeriveAttr::MaxSize(max_size_attr) => max_size = Some(max_size_attr.value),
                    DeriveAttr::NoMaxSizeErrors(_) => no_max_size_errors = true,
                }
            }
        }
    }
    match max_size {
        Some(max_size) => (max_size, no_max_size_errors),
        None => {
            let msg = "enum is missing `max_size` attribute: e.g. #[mh(max_size = U64)]";
            #[cfg(test)]
            panic!(msg);
            #[cfg(not(test))]
            proc_macro_error::abort!(&ast.ident, msg);
        }
    }
}

/// Return an error if the same code is used several times.
///
/// This only checks for string equality, though this should still catch most errors caused by
/// copy and pasting.
fn error_code_duplicates(hashes: &[Hash]) {
    // Use a temporary store to determine whether a certain value is unique or not
    let mut uniq = HashSet::new();

    hashes.iter().for_each(|hash| {
        let code = &hash.code;
        let msg = format!(
            "the #mh(code) attribute `{}` is defined multiple times",
            quote!(#code)
        );

        // It's a duplicate
        if !uniq.insert(code) {
            #[cfg(test)]
            panic!(msg);
            #[cfg(not(test))]
            {
                let already_defined = uniq.get(code).unwrap();
                let line = already_defined.to_token_stream().span().start().line;
                proc_macro_error::emit_error!(
                    &hash.code, msg;
                    note = "previous definition of `{}` at line {}", quote!(#code), line;
                );
            }
        }
    });
}

/// An error that contains a span in order to produce nice error messages.
#[derive(Debug)]
struct ParseError(proc_macro2::Span);

/// Parse a path containing a `typenum` unsigned integer (e.g. `U64`) into a u64
fn parse_unsigned_typenum(typenum_path: &syn::Type) -> Result<u64, ParseError> {
    match typenum_path {
        syn::Type::Path(type_path) => match type_path.path.segments.last() {
            Some(path_segment) => {
                let typenum_ident = &path_segment.ident;
                let typenum = typenum_ident.to_string();
                match typenum.as_str().split_at(1) {
                    ("U", byte_size) => byte_size
                        .parse::<u64>()
                        .map_err(|_| ParseError(typenum_ident.span())),
                    _ => Err(ParseError(typenum_ident.span())),
                }
            }
            None => Err(ParseError(type_path.path.span())),
        },
        _ => Err(ParseError(typenum_path.span())),
    }
}

/// Returns the max size as u64.
///
/// Emits an error if the `#mh(max_size)` attribute doesn't contain a valid unsigned integer
/// `typenum`.
fn parse_max_size_attribute(max_size: &syn::Type) -> u64 {
    parse_unsigned_typenum(&max_size).unwrap_or_else(|_| {
        let msg = "`max_size` attribute must be a `typenum`, e.g. #[mh(max_size = U64)]";
        #[cfg(test)]
        panic!(msg);
        #[cfg(not(test))]
        proc_macro_error::abort!(&max_size, msg);
    })
}

/// Return a warning/error if the specified max_size is smaller than the biggest digest
fn error_max_size(hashes: &[Hash], expected_max_size_type: &syn::Type) {
    let expected_max_size = parse_max_size_attribute(expected_max_size_type);

    let maybe_error: Result<(), ParseError> = hashes
        .iter()
        .map(|hash| {
            // The digest type must have a size parameter of the shape `U<number>`, else we error.
            match hash.digest.segments.last() {
                Some(path_segment) => match &path_segment.arguments {
                    syn::PathArguments::AngleBracketed(arguments) => match arguments.args.last() {
                        Some(syn::GenericArgument::Type(path)) => {
                            match parse_unsigned_typenum(&path) {
                                Ok(max_digest_size) => {
                                    if max_digest_size > expected_max_size {
                                        let msg = format!("The `#mh(max_size) attribute must be bigger than the maximum defined digest size (U{})",
                                        max_digest_size);
                                        #[cfg(test)]
                                        panic!(msg);
                                        #[cfg(not(test))]
                                        {
                                            let digest = &hash.digest.to_token_stream().to_string().replace(" ", "");
                                            let line = &hash.digest.span().start().line;
                                            proc_macro_error::emit_error!(
                                                &expected_max_size_type, msg;
                                                note = "the bigger digest is `{}` at line {}", digest, line;
                                            );
                                        }
                                    }
                                    Ok(())
                                },
                                Err(err) => Err(err),
                            }
                        },
                        _ => Err(ParseError(arguments.args.span())),
                    },
                    _ => Err(ParseError(path_segment.span())),
                },
                None => Err(ParseError(hash.digest.span())),
            }
        }).collect();

    if let Err(_error) = maybe_error {
        let msg = "Invalid byte size. It must be a unsigned integer typenum, e.g. `U32`";
        #[cfg(test)]
        panic!(msg);
        #[cfg(not(test))]
        {
            proc_macro_error::emit_error!(&_error.0, msg);
        }
    }
}

pub fn multihash(s: Structure) -> TokenStream {
    let mh_crate = utils::use_crate("tiny-multihash");
    let code_enum = &s.ast().ident;
    let (max_size, no_max_size_errors) = parse_code_enum_attrs(&s.ast());
    let hashes: Vec<_> = s.variants().iter().map(Hash::from).collect();

    error_code_duplicates(&hashes);

    if !no_max_size_errors {
        error_max_size(&hashes, &max_size);
    }

    let params = Params {
        mh_crate: mh_crate.clone(),
        code_enum: code_enum.clone(),
    };

    let code_into_u64 = hashes.iter().map(|h| h.code_into_u64(&params));
    let code_from_u64 = hashes.iter().map(|h| h.code_from_u64());
    let code_digest = hashes.iter().map(|h| h.code_digest(&params));
    let from_digest = hashes.iter().map(|h| h.from_digest(&params));

    quote! {
        impl #mh_crate::MultihashCode for #code_enum {
            type MaxSize = #max_size;

            fn digest(&self, input: &[u8]) -> #mh_crate::Multihash<Self::MaxSize> {
                use #mh_crate::Hasher;
                match self {
                    #(#code_digest,)*
                }
            }

            fn multihash_from_digest<'a, S, D>(digest: &'a D) -> #mh_crate::Multihash<Self::MaxSize>
            where
                S: #mh_crate::Size,
                D: #mh_crate::Digest<S>,
                Self: From<&'a D>,
            {
                let code = Self::from(&digest);
                #mh_crate::Multihash::wrap(code.into(), &digest.as_ref()).unwrap()
            }
        }

        impl From<#code_enum> for u64 {
            fn from(code: #code_enum) -> Self {
                match code {
                    #(#code_into_u64,)*
                }
            }
        }

        impl core::convert::TryFrom<u64> for #code_enum {
            type Error = #mh_crate::Error;

            fn try_from(code: u64) -> Result<Self, Self::Error> {
                match code {
                    #(#code_from_u64,)*
                    _ => Err(#mh_crate::Error::UnsupportedCode(code))
                }
            }
        }

        #(#from_digest)*
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multihash_derive() {
        let input = quote! {
           #[derive(Clone, Multihash)]
           #[mh(max_size = U32)]
           pub enum Code {
               #[mh(code = tiny_multihash::IDENTITY, hasher = tiny_multihash::Identity256, digest = tiny_multihash::IdentityDigest<U32>)]
               Identity256,
               /// Multihash array for hash function.
               #[mh(code = 0x38b64f, hasher = tiny_multihash::Strobe256, digest = tiny_multihash::StrobeDigest<U32>)]
               Strobe256,
            }
        };
        let expected = quote! {
            impl tiny_multihash::MultihashCode for Code {
               type MaxSize = U32;

               fn digest(&self, input: &[u8]) -> tiny_multihash::Multihash<Self::MaxSize> {
                   use tiny_multihash::Hasher;
                   match self {
                       Self::Identity256 => {
                           let digest = tiny_multihash::Identity256::digest(input);
                           tiny_multihash::Multihash::wrap(tiny_multihash::IDENTITY, &digest.as_ref()).unwrap()
                       },
                       Self::Strobe256 => {
                           let digest = tiny_multihash::Strobe256::digest(input);
                           tiny_multihash::Multihash::wrap(0x38b64f, &digest.as_ref()).unwrap()
                       },
                   }
               }

               fn multihash_from_digest<'a, S, D>(digest: &'a D) -> tiny_multihash::Multihash<Self::MaxSize>
               where
                   S: tiny_multihash::Size,
                   D: tiny_multihash::Digest<S>,
                   Self: From<&'a D>,
               {
                   let code = Self::from(&digest);
                   tiny_multihash::Multihash::wrap(code.into(), &digest.as_ref()).unwrap()
               }
            }


            impl From<Code> for u64 {
                fn from(code: Code) -> Self {
                    match code {
                        Code::Identity256 => tiny_multihash::IDENTITY,
                        Code::Strobe256 => 0x38b64f,
                    }
                }
            }

            impl core::convert::TryFrom<u64> for Code {
                type Error = tiny_multihash::Error;

                fn try_from(code: u64) -> Result<Self, Self::Error> {
                    match code {
                        tiny_multihash::IDENTITY => Ok(Self::Identity256),
                        0x38b64f => Ok(Self::Strobe256),
                        _ => Err(tiny_multihash::Error::UnsupportedCode(code))
                    }
                }
            }

            impl From<&tiny_multihash::IdentityDigest<U32> > for Code {
                fn from(digest: &tiny_multihash::IdentityDigest<U32>) -> Self {
                    Self::Identity256
                }
            }
            impl From<&tiny_multihash::StrobeDigest<U32> > for Code {
                fn from(digest: &tiny_multihash::StrobeDigest<U32>) -> Self {
                    Self::Strobe256
                }
            }
        };
        let derive_input = syn::parse2(input).unwrap();
        let s = Structure::new(&derive_input);
        let result = multihash(s);
        utils::assert_proc_macro(result, expected);
    }

    #[test]
    #[should_panic(
        expected = "the #mh(code) attribute `tiny_multihash :: SHA2_256` is defined multiple times"
    )]
    fn test_multihash_error_code_duplicates() {
        let input = quote! {
           #[derive(Clone, Multihash)]
           #[mh(max_size = U64)]
           pub enum Multihash {
               #[mh(code = tiny_multihash::SHA2_256, hasher = tiny_multihash::Sha2_256, digest = tiny_multihash::Sha2Digest<U32>)]
               Identity256,
               #[mh(code = tiny_multihash::SHA2_256, hasher = tiny_multihash::Sha2_256, digest = tiny_multihash::Sha2Digest<U32>)]
               Identity256,
            }
        };
        let derive_input = syn::parse2(input).unwrap();
        let s = Structure::new(&derive_input);
        multihash(s);
    }

    #[test]
    #[should_panic(expected = "the #mh(code) attribute `0x14` is defined multiple times")]
    fn test_multihash_error_code_duplicates_numbers() {
        let input = quote! {
           #[derive(Clone, Multihash)]
           #[mh(max_size = U32)]
           pub enum Code {
               #[mh(code = 0x14, hasher = tiny_multihash::Sha2_256, digest = tiny_multihash::Sha2Digest<U32>)]
               Identity256,
               #[mh(code = 0x14, hasher = tiny_multihash::Sha2_256, digest = tiny_multihash::Sha2Digest<U32>)]
               Identity256,
            }
        };
        let derive_input = syn::parse2(input).unwrap();
        let s = Structure::new(&derive_input);
        multihash(s);
    }

    #[test]
    #[should_panic(expected = "enum is missing `max_size` attribute: e.g. #[mh(max_size = U64)]")]
    fn test_multihash_error_no_max_size() {
        let input = quote! {
           #[derive(Clone, Multihash)]
           pub enum Code {
               #[mh(code = 0x14, hasher = tiny_multihash::Sha2_256, digest = tiny_multihash::Sha2Digest<U32>)]
               Sha2_256,
            }
        };
        let derive_input = syn::parse2(input).unwrap();
        let s = Structure::new(&derive_input);
        multihash(s);
    }

    #[test]
    #[should_panic(
        expected = "The `#mh(max_size) attribute must be bigger than the maximum defined digest size (U32)"
    )]
    fn test_multihash_error_too_small_max_size() {
        let input = quote! {
           #[derive(Clone, Multihash)]
           #[mh(max_size = U16)]
           pub enum Code {
               #[mh(code = 0x14, hasher = tiny_multihash::Sha2_256, digest = tiny_multihash::Sha2Digest<U32>)]
               Sha2_256,
            }
        };
        let derive_input = syn::parse2(input).unwrap();
        let s = Structure::new(&derive_input);
        multihash(s);
    }

    #[test]
    #[should_panic(
        expected = "Invalid byte size. It must be a unsigned integer typenum, e.g. `U32`"
    )]
    fn test_multihash_error_digest_invalid_size_type() {
        let input = quote! {
           #[derive(Clone, Multihash)]
           #[mh(max_size = U32)]
           pub enum Code {
               #[mh(code = 0x14, hasher = tiny_multihash::Sha2_256, digest = tiny_multihash::Sha2Digest<foo>)]
               Sha2_256,
            }
        };
        let derive_input = syn::parse2(input).unwrap();
        let s = Structure::new(&derive_input);
        multihash(s);
    }

    #[test]
    #[should_panic(
        expected = "Invalid byte size. It must be a unsigned integer typenum, e.g. `U32`"
    )]
    fn test_multihash_error_digest_invalid_size_type2() {
        let input = quote! {
           #[derive(Clone, Multihash)]
           #[mh(max_size = U32)]
           pub enum Code {
               #[mh(code = 0x14, hasher = tiny_multihash::Sha2_256, digest = tiny_multihash::Sha2Digest<_>)]
               Sha2_256,
            }
        };
        let derive_input = syn::parse2(input).unwrap();
        let s = Structure::new(&derive_input);
        multihash(s);
    }

    #[test]
    #[should_panic(
        expected = "Invalid byte size. It must be a unsigned integer typenum, e.g. `U32`"
    )]
    fn test_multihash_error_digest_without_typenum() {
        let input = quote! {
           #[derive(Clone, Multihash)]
           #[mh(max_size = U32)]
           pub enum Code {
               #[mh(code = 0x14, hasher = tiny_multihash::Sha2_256, digest = Sha2_256Digest)]
               Sha2_256,
            }
        };
        let derive_input = syn::parse2(input).unwrap();
        let s = Structure::new(&derive_input);
        multihash(s);
    }

    // This one does not panic, die to `no_max_size_errors`
    #[test]
    fn test_multihash_error_digest_without_typenum_no_max_size_errors() {
        let input = quote! {
           #[derive(Clone, Multihash)]
           #[mh(max_size = U32, no_max_size_errors)]
           pub enum Code {
               #[mh(code = 0x14, hasher = tiny_multihash::Sha2_256, digest = Sha2_256Digest)]
               Sha2_256,
            }
        };
        let derive_input = syn::parse2(input).unwrap();
        let s = Structure::new(&derive_input);
        multihash(s);
    }
}
