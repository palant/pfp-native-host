macro_rules! numeric_enum {
    ($name:ident = $type:ident($error:ident) {
        $(
            $(#[$meta:ident])*
            $variant:ident = $value:literal,
        )*
    }) => {
        $($(
            numeric_enum!{@ignore $meta}
            #[derive(Default)]
        )*)*
        #[derive(Debug)]
        pub(crate) enum $name {
            $(
                $(#[$meta])*
                $variant,
            )+
        }

        impl $name {
            #[allow(dead_code)]
            pub const SIZE: usize = ($type::BITS / 8) as usize;
        }

        impl From<&$name> for $type {
            fn from(value: &$name) -> Self {
                match value {
                    $(
                        $name::$variant => $value,
                    )+
                }
            }
        }

        impl TryFrom<$type> for $name {
            type Error = crate::Error;
            fn try_from(value: $type) -> Result<Self, Self::Error> {
                match value {
                    $(
                        $value => Ok($name::$variant),
                    )+
                    _ => Err(Self::Error::$error(value)),
                }
            }
        }

        impl crate::io::Serialize for $name {
            fn serialize<W: std::io::Write>(&self, output: &mut W) -> Result<(), crate::Error> {
                $type::from(self).serialize(output)
            }
        }

        impl crate::io::Deserialize for $name {
            fn deserialize<R: std::io::Read>(input: &mut R) -> Result<Self, crate::Error> {
                $type::deserialize(input)?.try_into()
            }
        }
    };
    {@ignore $var:ident} => {};
}

pub(crate) use numeric_enum;
