// Make all generated proto stubs publically accessible
include!("generated/src/include.rs");

pub const FILE_DESCRIPTOR_SET_PATH: &str = concat!(
    env!("CARGO_WORKSPACE_DIR"),
    "lib/proto/generated/bin/descriptor.bin"
);
