//! Provides a macro to simplify declaring error enums. An error type is
//! declared as follows:
//!
//! ```ignore
//! error_enum::declare!{
//!     pub enum Error {
//!         Database(DatabaseError{serde_json::Error, some_crate::Error}),
//!         Io(std::io::Error),
//!         ///Unexpected error occurred
//!         UnexpectedError,
//!         ///The value {} is not supported
//!         InvalidValue(u32),
//!     }
//! }
//! ```
//!
//! Four types of enum entries are supported:
//!
//! * `Database(DatabaseError{serde_json::Error, some_crate::Error})` wraps
//!   another error enum type. The error types `serde_json::Error` and
//!   `some_crate::Error` are wrapped by that error enum, `From<>` trait
//!   implementations for these types should delegate to the wrapped enum.
//! * `Io(std::io::Error)` wraps an external error type.
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
/// ```ignore
/// error_enum::declare!{
///     pub enum Error {
///         Database(DatabaseError{serde_json::Error, some_crate::Error}),
///         Io(std::io::Error),
///         ///Unexpected error occurred
///         UnexpectedError,
///         ///The value {} is not supported
///         InvalidValue(u32),
///     }
/// }
/// ```

#[macro_export]
macro_rules! declare {
    {$visibility:vis enum $type:ident {
        $($variants:tt)*
    }} => {
        $crate::declare_type!{$visibility $type [] $($variants)*}
        $crate::impl_from!{$type $($variants)*}
        $crate::impl_code!{$type [] $($variants)*}
        $crate::impl_display!{$type [] $($variants)*}
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! declare_type {
    {$visibility:vis $type:ident [$($variants:tt)*] #[doc=$doc:literal] $name:ident, $($rest:tt)*} => {
        $crate::declare_type!{$visibility $type [
            $($variants)*
            #[doc=$doc]
            $name,
        ]  $($rest)*}
    };
    {$visibility:vis $type:ident [$($variants:tt)*] #[doc=$doc:literal] $name:ident($inner:ty), $($rest:tt)*} => {
        $crate::declare_type!{$visibility $type [
            $($variants)*
            #[doc=$doc]
            $name($inner),
        ] $($rest)*}
    };
    {$visibility:vis $type:ident [$($variants:tt)*] $name:ident($inner:ty), $($rest:tt)*} => {
        $crate::declare_type!{$visibility $type [
            $($variants)*
            #[doc=concat!("Wrapping ", stringify!($inner), " error type")]
            $name($inner),
        ] $($rest)*}
    };
    {$visibility:vis $type:ident [$($variants:tt)*] $name:ident($inner:ty{$($other:ty),*}), $($rest:tt)*} => {
        $crate::declare_type!{$visibility $type [
            $($variants)*
            #[doc=concat!("Wrapping ", stringify!($inner), " error type")]
            $name($inner),
        ] $($rest)*}
    };
    {$visibility:vis $type:ident [$($variants:tt)*]} => {
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
