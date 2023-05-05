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
