use crate::numeric_enum;

numeric_enum! {
    OuterHeaderFieldType as u8 with error UnsupportedHeaderFieldType {
        EndOfHeader = 0,
        Comment = 1,
        Cipher = 2,
        Compression = 3,
        MainSeed = 4,
        InitializationVector = 7,
        KdfParameters = 11,
        CustomData = 12,
    }
}

numeric_enum! {
    InnerHeaderFieldType as u8 with error UnsupportedHeaderFieldType {
        EndOfHeader = 0,
        StreamCipher = 1,
        StreamKey = 2,
        Binary = 3,
    }
}
