//! Provides a macro to simplify declaring error enums. An error type is
//! declared as follows:
//!
//! ```
//! error_enum::declare!{
//!     /// Error type returned by database operations
//!     pub enum DatabaseError {
//!         Io(std::io::Error),
//!         Encoding(std::str::Utf8Error),
//!         ///The database file is corrupt
//!         CorruptDatabase,
//!     }
//! }
//!
//! error_enum::declare!{
//!     /// Generic error type
//!     pub enum Error {
//!         Database(DatabaseError{std::io::Error, std::str::Utf8Error}),
//!         Parsing(std::num::ParseIntError),
//!         ///Unexpected error occurred
//!         UnexpectedError,
//!         ///The value {} is not supported
//!         InvalidValue(u32),
//!     }
//! }
//!
//! let io_error = Error::from(std::io::Error::new(std::io::ErrorKind::Other, "oh no!"));
//! assert_eq!(io_error.code(), "Io");
//! assert_eq!(format!("{io_error}"), "oh no!");
//!
//! let parse_error = Error::from(u32::from_str_radix("abc", 10).unwrap_err());
//! assert_eq!(parse_error.code(), "Parsing");
//! assert_eq!(
//!     format!("{parse_error}"),
//!     format!("{}", u32::from_str_radix("abc", 10).unwrap_err())
//! );
//!
//! let unexpected_error = Error::UnexpectedError;
//! assert_eq!(unexpected_error.code(), "UnexpectedError");
//! assert_eq!(format!("{unexpected_error}"), "Unexpected error occurred");
//!
//! let value_error = Error::InvalidValue(12);
//! assert_eq!(value_error.code(), "InvalidValue");
//! assert_eq!(format!("{value_error}"), "The value 12 is not supported");
//! ```
//!
//! Four types of enum entries are supported:
//!
//! * `Database(DatabaseError{std::io::Error, std::str::Utf8Error})` wraps
//!   another error enum type. The error types `std::io::Error` and
//!   `std::str::Utf8Error` are wrapped by that error enum, `From<>` trait
//!   implementations for these types should delegate to the wrapped enum.
//! * `Parsing(std::num::ParseIntError)` wraps an external error type.
//! * `UnexpectedError` is a plain error variant, doc comment is mandatory.
//! * `InvalidValue(u32)` is a parametrized error variant, doc comment is mandatory.
//!
//! The following traits are being automatically implemented:
//!
//! * `Debug`
//! * `Display`: For wrapped errors, the implementation defers to their
//!   `Display` implementation. For other variants, the doc comment is used as
//!   format string.
//! * `From<OtherError>`: This is implemented for all wrapped error types as
//!   well as declared wrapped error types for wrapped error enums.
//!
//! In addition, a public method `code()` is implemented. It returns the
//! variant name. For wrapped error enums it defers to their `code()` method.

/// Declares an error enum type and implements the required traits:
///
/// ```
/// error_enum::declare!{
///     /// Error type returned by database operations
///     pub enum DatabaseError {
///         Io(std::io::Error),
///         Encoding(std::str::Utf8Error),
///         ///The database file is corrupt
///         CorruptDatabase,
///     }
/// }
///
/// error_enum::declare!{
///     /// Generic error type
///     pub enum Error {
///         Database(DatabaseError{std::io::Error, std::str::Utf8Error}),
///         Parsing(std::num::ParseIntError),
///         ///Unexpected error occurred
///         UnexpectedError,
///         ///The value {} is not supported
///         InvalidValue(u32),
///     }
/// }
/// ```

#[macro_export]
macro_rules! declare {
    {$(#[$meta:meta])* $visibility:vis enum $type:ident {
        $($variants:tt)*
    }} => {
        $crate::declare_type!{#[$($meta)*] $visibility $type [] $($variants)*}
        $crate::impl_from!{$type $($variants)*}
        $crate::impl_code!{$type [] $($variants)*}
        $crate::impl_display!{$type [] $($variants)*}
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! declare_type {
    {#[$($meta:meta)*] $visibility:vis $type:ident [$($variants:tt)*] #[doc=$doc:literal] $name:ident, $($rest:tt)*} => {
        $crate::declare_type!{#[$($meta)*] $visibility $type [
            $($variants)*
            #[doc=$doc]
            $name,
        ]  $($rest)*}
    };
    {#[$($meta:meta)*] $visibility:vis $type:ident [$($variants:tt)*] #[doc=$doc:literal] $name:ident($inner:ty), $($rest:tt)*} => {
        $crate::declare_type!{#[$($meta)*] $visibility $type [
            $($variants)*
            #[doc=$doc]
            $name($inner),
        ] $($rest)*}
    };
    {#[$($meta:meta)*] $visibility:vis $type:ident [$($variants:tt)*] $name:ident($inner:ty), $($rest:tt)*} => {
        $crate::declare_type!{#[$($meta)*] $visibility $type [
            $($variants)*
            #[doc=concat!("Wrapping ", stringify!($inner), " error type")]
            $name($inner),
        ] $($rest)*}
    };
    {#[$($meta:meta)*] $visibility:vis $type:ident [$($variants:tt)*] $name:ident($inner:ty{$($other:ty),*}), $($rest:tt)*} => {
        $crate::declare_type!{#[$($meta)*] $visibility $type [
            $($variants)*
            #[doc=concat!("Wrapping ", stringify!($inner), " error type")]
            $name($inner),
        ] $($rest)*}
    };
    {#[$($meta:meta)*] $visibility:vis $type:ident [$($variants:tt)*]} => {
        $(
            #[$meta]
        )*
        #[derive(Debug)]
        $visibility enum $type {
            $($variants)*
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! impl_from {
    {$type:ident} => {};
    {$type:ident #[doc=$doc:literal] $name:ident, $($rest:tt)*} => {
        $crate::impl_from!{$type $($rest)*}
    };
    {$type:ident #[doc=$doc:literal] $name:ident($inner:ty), $($rest:tt)*} => {
        $crate::impl_from!{$type $($rest)*}
    };
    {$type:ident $name:ident($inner:ty), $($rest:tt)*} => {
        $crate::impl_from!{$type $name($inner{}),}
        $crate::impl_from!{$type $($rest)*}
    };
    {$type:ident $name:ident($inner:ty{$($other:ty),*}), $($rest:tt)*} => {
        impl From<$inner> for $type {
            fn from(value: $inner) -> Self {
                Self::$name(value)
            }
        }
        $(
            impl From<$other> for $type {
                fn from(value: $other) -> Self {
                    <$inner>::from(value).into()
                }
            }
        )*
        $crate::impl_from!{$type $($rest)*}
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! impl_code {
    {$type:ident [$($variants:tt)*] #[doc=$doc:literal] $name:ident, $($rest:tt)*} => {
        $crate::impl_code!{$type [
            $($variants)*
            Self::$name => stringify!($name),
        ]  $($rest)*}
    };
    {$type:ident [$($variants:tt)*] #[doc=$doc:literal] $name:ident($inner:ty), $($rest:tt)*} => {
        $crate::impl_code!{$type [
            $($variants)*
            Self::$name(_) => stringify!($name),
        ] $($rest)*}
    };
    {$type:ident [$($variants:tt)*] $name:ident($inner:ty), $($rest:tt)*} => {
        $crate::impl_code!{$type [
            $($variants)*
            Self::$name(_) => stringify!($name),
        ] $($rest)*}
    };
    {$type:ident [$($variants:tt)*] $name:ident($inner:ty{$($other:ty),*}), $($rest:tt)*} => {
        $crate::impl_code!{$type [
            $($variants)*
            Self::$name(inner) => inner.code(),
        ] $($rest)*}
    };
    {$type:ident [$($variants:tt)*]} => {
        impl $type {
            #[allow(dead_code)]
            pub fn code(&self) -> &'static str {
                match self {
                    $($variants)*
                }
            }
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! impl_display {
    {$type:ident [$($variants:tt)*] #[doc=$doc:literal] $name:ident, $($rest:tt)*} => {
        $crate::impl_display!{$type [
            $($variants)*
            (Self::$name, f) => write!(f, $doc),
        ]  $($rest)*}
    };
    {$type:ident [$($variants:tt)*] #[doc=$doc:literal] $name:ident($inner:ty), $($rest:tt)*} => {
        $crate::impl_display!{$type [
            $($variants)*
            (Self::$name(inner), f) => write!(f, $doc, inner),
        ] $($rest)*}
    };
    {$type:ident [$($variants:tt)*] $name:ident($inner:ty), $($rest:tt)*} => {
        $crate::impl_display!{$type [
            $($variants)*
            (Self::$name(inner), f) => inner.fmt(f),
        ] $($rest)*}
    };
    {$type:ident [$($variants:tt)*] $name:ident($inner:ty{$($other:ty),*}), $($rest:tt)*} => {
        $crate::impl_display!{$type [
            $($variants)*
            (Self::$name(inner), f) => inner.fmt(f),
        ] $($rest)*}
    };
    {$type:ident [$($variants:tt)*]} => {
        impl std::fmt::Display for $type {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match (self, f) {
                    $($variants)*
                }
            }
        }
    };
}
