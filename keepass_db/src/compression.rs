use crate::numeric_enum;

numeric_enum!(Compression=u32(UnsupportedCompression) {
    None = 0,
    #[default]
    Gzip = 1,
});
