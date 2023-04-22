#![deny(elided_lifetimes_in_paths)]
#![deny(explicit_outlives_requirements)]
#![deny(keyword_idents)]
#![deny(meta_variable_misuse)]
#![deny(missing_debug_implementations)]
#![deny(non_ascii_idents)]
#![warn(noop_method_call)]
#![deny(pointer_structural_match)]
#![deny(single_use_lifetimes)]
#![deny(trivial_casts)]
#![deny(trivial_numeric_casts)]
#![deny(unsafe_code)]
#![deny(unused_crate_dependencies)]
#![deny(unused_import_braces)]
#![deny(unused_lifetimes)]
#![warn(unused_macro_rules)]
#![warn(unused_tuple_struct_fields)]
#![deny(variant_size_differences)]

mod binary;
mod cipher;
mod compression;
mod database;
pub mod database_header;
pub mod database_version;
pub mod database_xml;
pub mod entry;
pub mod error;
mod header_field_type;
mod hmac_block_stream;
pub mod io;
pub mod kdf_parameters;
pub mod keys;
mod numeric_enum;
mod random;
mod variant_field;
mod variant_list;
mod xml_helpers;

pub(crate) use self::cipher::*;
pub(crate) use binary::*;
pub(crate) use compression::*;
pub use database::*;
pub use database_header::*;
pub(crate) use database_version::*;
pub use database_xml::*;
pub use entry::*;
pub use error::*;
pub(crate) use header_field_type::*;
pub(crate) use hmac_block_stream::*;
pub use kdf_parameters::*;
pub use keys::*;
pub(crate) use numeric_enum::*;
pub(crate) use variant_field::*;
pub(crate) use variant_list::*;
pub(crate) use xml_helpers::*;
