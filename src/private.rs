//! Small handle-based primitives for private filesystem storage.
//!
//! These functions do not choose an application's trust policy. They never
//! resolve an unvalidated pathname relative to the process working directory.
//! Child operations accept exactly one ordinary Windows filename component.
mod buffer;
#[cfg(test)]
mod dedicated_tests;
mod directory;
mod directory_records;
mod fs;
mod security;
mod temporary;

pub use directory::{directory_names, DirectoryNames};
pub use fs::{
    check_name, create_directory, create_directory_read, create_file, flush_directory, open_child,
    open_root, open_volume_root, pin_directory, read_reparse_target, remove, rename, Access, Kind,
};
pub use security::{
    security_info, set_dacl, set_dacl_only, Ace, AceKind, SecurityInfo, SecurityTemplate, Sid,
};
pub use temporary::temporary_directory;

fn invalid() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "invalid Windows filesystem metadata",
    )
}
