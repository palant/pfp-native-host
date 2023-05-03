use crate::numeric_enum;

numeric_enum! {
    /// KeePass database compression type
    #[derive(Default)]
    Compression as u32 with error UnsupportedCompression {
        /// Uncompressed database
        None = 0,
        /// Gzip compression
        #[default]
        Gzip = 1,
    }
}
