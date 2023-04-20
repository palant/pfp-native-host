use crate::numeric_enum;

numeric_enum! {
    #[derive(Default)]
    Compression as u32 with error UnsupportedCompression {
        None = 0,
        #[default]
        Gzip = 1,
    }
}
