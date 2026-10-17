use super::{
    buffer::{u16_at, u32_at, Buffer},
    invalid, SecurityTemplate,
};
use std::os::windows::{
    ffi::{OsStrExt, OsStringExt},
    io::{AsHandle, AsRawHandle, FromRawHandle},
};
use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io, mem,
    path::PathBuf,
    ptr,
};
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    NtCreateFile, NtFlushBuffersFileEx, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE,
    FILE_OPEN, FILE_OPEN_REPARSE_POINT, FILE_RENAME_POSIX_SEMANTICS, FILE_RENAME_REPLACE_IF_EXISTS,
    FILE_SYNCHRONOUS_IO_NONALERT,
};
use windows_sys::Win32::Foundation::{
    RtlNtStatusToDosError, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FileDispositionInfoEx, FileRenameInfo, FileRenameInfoEx,
    GetVolumeInformationByHandleW, ReOpenFile, SetFileInformationByHandle, DELETE, FILE_ADD_FILE,
    FILE_ADD_SUBDIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_DISPOSITION_FLAG_DELETE,
    FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO_EX, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_RENAME_INFO,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL, SYNCHRONIZE,
    WRITE_DAC,
};
use windows_sys::Win32::System::Ioctl::FSCTL_GET_REPARSE_POINT;
use windows_sys::Win32::System::SystemServices::{
    FILE_PERSISTENT_ACLS, IO_REPARSE_TAG_MOUNT_POINT, IO_REPARSE_TAG_SYMLINK,
};
use windows_sys::Win32::System::IO::{DeviceIoControl, IO_STATUS_BLOCK};

#[derive(Clone, Copy, Debug)]
pub enum Kind {
    File,
    Directory,
    Any,
}

#[derive(Clone, Copy, Debug)]
pub enum Access {
    /// Read/traverse and inspect security, without permission mutation.
    Read,
    /// Read, change the DACL, and remove/rename the held object.
    Manage,
    /// Read/write private staging data, change DACL, remove/rename.
    ReadWrite,
}

/// Require one literal filename component. Native stream/device syntax and
/// Win32-trimmed names are disallowed so a later path consumer sees the same name.
pub fn check_name(name: &OsStr) -> io::Result<()> {
    let wide: Vec<u16> = name.encode_wide().collect();
    if wide.is_empty()
        || wide.len() > 255
        || name == "."
        || name == ".."
        || matches!(wide.last(), Some(32 | 46))
        || wide
            .iter()
            .any(|&c| c < 32 || matches!(c, 34 | 42 | 47 | 58 | 60 | 62 | 63 | 92 | 124))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected one ordinary Windows filename",
        ));
    }
    let mut stem: Vec<u16> = wide
        .iter()
        .copied()
        .take_while(|&c| c != 46)
        .map(|c| if (97..=122).contains(&c) { c - 32 } else { c })
        .collect();
    while stem.last() == Some(&32) {
        stem.pop();
    }
    let fixed = ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"];
    let reserved = fixed
        .iter()
        .any(|value| stem.iter().copied().eq(value.encode_utf16()))
        || (stem.len() == 4
            && (stem[..3] == [67, 79, 77] || stem[..3] == [76, 80, 84])
            && matches!(stem[3], 49..=57 | 0x00b9 | 0x00b2 | 0x00b3));
    if reserved {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "reserved Windows filename",
        ));
    }
    Ok(())
}

fn rights(access: Access) -> u32 {
    let read = READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_READ_DATA | SYNCHRONIZE;
    match access {
        Access::Read => read,
        Access::Manage => read | WRITE_DAC | DELETE,
        Access::ReadWrite => read | WRITE_DAC | DELETE | GENERIC_WRITE,
    }
}

/// Open a local drive root. Child resolution is exclusively handle-relative.
/// Device paths and UNC roots are not accepted by this deliberately narrow API.
pub fn open_root(drive: u8) -> io::Result<File> {
    if !drive.is_ascii_alphabetic() {
        return Err(invalid());
    }
    let path: Vec<u16> = format!("\\\\?\\{}:\\", char::from(drive))
        .encode_utf16()
        .chain(Some(0))
        .collect();
    open_root_path(&path)
}

/// Open the exact local volume GUID prefix used by a mounted-folder junction.
/// Other verbatim/device namespaces are rejected before calling Windows.
pub fn open_volume_root(volume: &OsStr) -> io::Result<File> {
    let name = volume.to_str().ok_or_else(invalid)?;
    if name.len() != 44
        || !name.is_ascii()
        || !name[..7].eq_ignore_ascii_case("Volume{")
        || !name.ends_with('}')
    {
        return Err(invalid());
    }
    for (index, byte) in name.as_bytes()[7..43].iter().copied().enumerate() {
        if [8, 13, 18, 23].contains(&index) {
            if byte != b'-' {
                return Err(invalid());
            }
        } else if !byte.is_ascii_hexdigit() {
            return Err(invalid());
        }
    }
    let path: Vec<u16> = format!("\\\\?\\{name}\\")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    open_root_path(&path)
}

fn open_root_path(path: &[u16]) -> io::Result<File> {
    // SAFETY: path is terminated and lives through the call, attributes null,
    // and the returned handle has exactly one owner on success.
    let raw = unsafe {
        CreateFileW(
            path.as_ptr(),
            rights(Access::Read),
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            HANDLE::default(),
        )
    };
    let file = owned_file(raw)?;
    let mut flags = 0;
    // SAFETY: only flags is requested, with a valid owned directory handle.
    let ok = unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle() as HANDLE,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut flags,
            ptr::null_mut(),
            0,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    if flags & FILE_PERSISTENT_ACLS == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private storage requires persistent filesystem ACLs",
        ));
    }
    Ok(file)
}

/// Open exactly one component without following a terminal reparse point.
pub fn open_child<P: AsHandle>(
    parent: P,
    name: &OsStr,
    kind: Kind,
    access: Access,
) -> io::Result<File> {
    open_at(parent, name, kind, access, None)
}

/// Create a new directory with a protected DACL in the atomic create operation.
pub fn create_directory<P: AsHandle>(
    parent: P,
    name: &OsStr,
    security: &SecurityTemplate,
) -> io::Result<File> {
    open_at(
        parent,
        name,
        Kind::Directory,
        Access::ReadWrite,
        Some(security),
    )
}

/// Create an owned directory without requesting DELETE access on its handle.
/// This handle can be pinned without a close/reopen-by-name interval.
pub fn create_directory_read<P: AsHandle>(
    parent: P,
    name: &OsStr,
    security: &SecurityTemplate,
) -> io::Result<File> {
    open_at(parent, name, Kind::Directory, Access::Read, Some(security))
}

/// Reopen the same directory or directory reparse object with no delete sharing.
/// The returned handle prevents rename/removal while allowing child IO. An
/// existing DELETE handle conflicts; callers must create with read access when
/// they need to pin a new directory without releasing its identity.
pub fn pin_directory<F: AsHandle>(file: F) -> io::Result<File> {
    let metadata = crate::winapi_util::file::information(&file)?;
    if !crate::winapi_util::file::typ(&file)?.is_disk() || metadata.file_attributes() & 0x10 == 0 {
        return Err(invalid());
    }
    // SAFETY: ReOpenFile borrows a live handle and returns a separately owned
    // handle to that object. OPEN_REPARSE_POINT preserves a held link identity.
    let raw = unsafe {
        ReOpenFile(
            file.as_handle().as_raw_handle() as HANDLE,
            rights(Access::Read),
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        )
    };
    owned_file(raw)
}

/// Create a new regular file with a protected DACL; never truncate an existing object.
pub fn create_file<P: AsHandle>(
    parent: P,
    name: &OsStr,
    security: &SecurityTemplate,
) -> io::Result<File> {
    open_at(parent, name, Kind::File, Access::ReadWrite, Some(security))
}

fn open_at<P: AsHandle>(
    parent: P,
    name: &OsStr,
    kind: Kind,
    access: Access,
    security: Option<&SecurityTemplate>,
) -> io::Result<File> {
    check_name(name)?;
    let name: Vec<u16> = name.encode_wide().collect();
    let length = u16::try_from(name.len() * 2).map_err(|_| invalid())?;
    let unicode = UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: name.as_ptr() as *mut u16,
    };
    let parent = parent.as_handle();
    let attributes = OBJECT_ATTRIBUTES {
        Length: mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle() as HANDLE,
        ObjectName: &unicode,
        Attributes: 0x40, // OBJ_CASE_INSENSITIVE, deliberately not OBJ_INHERIT
        SecurityDescriptor: security.map_or(ptr::null(), SecurityTemplate::as_ptr),
        SecurityQualityOfService: ptr::null(),
    };
    let kind_flags = match kind {
        Kind::File => FILE_NON_DIRECTORY_FILE,
        Kind::Directory => FILE_DIRECTORY_FILE,
        Kind::Any => 0,
    };
    let mut raw = INVALID_HANDLE_VALUE;
    let mut status: IO_STATUS_BLOCK = unsafe { mem::zeroed() };
    // SAFETY: every pointer is backed by initialized storage alive for this
    // synchronous call. RootDirectory is borrowed. No returned handle escapes
    // unowned. The kernel receives a single component and OPEN_REPARSE_POINT.
    let result = unsafe {
        NtCreateFile(
            &mut raw,
            rights(access),
            &attributes,
            &mut status,
            ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            if security.is_some() {
                FILE_CREATE
            } else {
                FILE_OPEN
            },
            kind_flags | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            ptr::null(),
            0,
        )
    };
    nt_result(result)?;
    owned_file(raw)
}

fn owned_file(raw: HANDLE) -> io::Result<File> {
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    if raw == HANDLE::default() {
        return Err(invalid());
    }
    // SAFETY: callers transfer exactly one successfully returned owned handle.
    Ok(unsafe { File::from_raw_handle(raw as _) })
}

pub(super) fn reopen_for_dacl<F: AsHandle>(file: F) -> io::Result<File> {
    // ReOpenFile addresses the object referenced by the original handle, never
    // its former pathname. This supports callers holding a read-only File.
    let raw = unsafe {
        ReOpenFile(
            file.as_handle().as_raw_handle() as HANDLE,
            READ_CONTROL | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_FLAG_BACKUP_SEMANTICS,
        )
    };
    owned_file(raw)
}

pub(super) fn nt_result(status: i32) -> io::Result<()> {
    if status < 0 {
        // SAFETY: pure NTSTATUS-to-Win32 translation.
        return Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(status) } as i32,
        ));
    }
    Ok(())
}

/// Rename the held source into a held destination directory. A false replace
/// flag provides the kernel's atomic no-replace behavior, never check-then-move.
pub fn rename<F: AsHandle, P: AsHandle>(
    file: F,
    parent: P,
    name: &OsStr,
    replace: bool,
) -> io::Result<()> {
    check_name(name)?;
    let wide: Vec<u16> = name.encode_wide().collect();
    let mut header: FILE_RENAME_INFO = unsafe { mem::zeroed() };
    let offset = ptr::addr_of_mut!(header.FileName) as usize - ptr::addr_of!(header) as usize;
    let length = mem::size_of::<FILE_RENAME_INFO>().max(offset + wide.len() * 2);
    let mut buffer = Buffer::new(length)?;
    let out = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    // SAFETY: buffer is pointer-aligned and at least the complete struct size.
    // Write fields individually so initialized zero padding remains initialized.
    unsafe {
        ptr::addr_of_mut!((*out).Anonymous.Flags).write(if replace {
            FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS
        } else {
            0
        });
        ptr::addr_of_mut!((*out).RootDirectory).write(parent.as_handle().as_raw_handle() as HANDLE);
        ptr::addr_of_mut!((*out).FileNameLength).write((wide.len() * 2) as u32);
    }
    for (slot, value) in buffer.bytes_mut()[offset..offset + wide.len() * 2]
        .chunks_exact_mut(2)
        .zip(wide)
    {
        slot.copy_from_slice(&value.to_le_bytes());
    }
    let ok = unsafe {
        SetFileInformationByHandle(
            file.as_handle().as_raw_handle() as HANDLE,
            if replace {
                FileRenameInfoEx
            } else {
                FileRenameInfo
            },
            buffer.as_ptr(),
            length as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Mark this admitted object for deletion; no pathname is reopened or unlinked.
/// Namespace removal completes when the deleting handle closes; already-open
/// readers retain their object. Requires Windows' extended POSIX disposition.
pub fn remove<F: AsHandle>(file: F) -> io::Result<()> {
    let disposition = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
    };
    let ok = unsafe {
        SetFileInformationByHandle(
            file.as_handle().as_raw_handle() as HANDLE,
            FileDispositionInfoEx,
            ptr::addr_of!(disposition).cast(),
            mem::size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Flush directory metadata through a new handle to this same object. Unlike a
/// read-only std File::sync_all, NtFlushBuffersFileEx requires write/append access.
/// Errors are returned even when the preceding namespace mutation succeeded.
pub fn flush_directory<F: AsHandle>(directory: F) -> io::Result<()> {
    let raw = unsafe {
        ReOpenFile(
            directory.as_handle().as_raw_handle() as HANDLE,
            FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_FLAG_BACKUP_SEMANTICS,
        )
    };
    let file = owned_file(raw)?;
    let mut status: IO_STATUS_BLOCK = unsafe { mem::zeroed() };
    let result = unsafe {
        NtFlushBuffersFileEx(
            file.as_raw_handle() as HANDLE,
            0,
            ptr::null(),
            0,
            &mut status,
        )
    };
    nt_result(result)
}

/// Read a symlink/junction from its held reparse handle. Unknown reparse tags,
/// invalid UTF-16 byte ranges, and non-DOS absolute targets are rejected.
/// Both synchronous and overlapped filesystem handles are accepted. Reopening
/// the held object can fail; such errors are returned before issuing the query.
pub fn read_reparse_target<F: AsHandle>(file: F) -> io::Result<PathBuf> {
    let file = synchronous_reparse_handle(file)?;
    let mut buffer = Buffer::new(16_384)?;
    let mut returned = 0;
    // SAFETY: the owned handle is synchronous, so DeviceIoControl completes
    // before the initialized output storage is inspected or dropped. A null
    // OVERLAPPED is valid regardless of how the caller opened its handle.
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle() as HANDLE,
            FSCTL_GET_REPARSE_POINT,
            ptr::null(),
            0,
            buffer.as_mut_ptr(),
            16_384,
            &mut returned,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    parse_reparse(
        buffer
            .bytes()
            .get(..returned as usize)
            .ok_or_else(invalid)?,
    )
}

fn synchronous_reparse_handle<F: AsHandle>(file: F) -> io::Result<File> {
    // SAFETY: ReOpenFile borrows the live handle and returns a separately owned
    // handle to the same filesystem object, without resolving a pathname.
    // OPEN_REPARSE_POINT prevents following the held link. Omitting OVERLAPPED
    // ensures synchronous IOCTL completion; BACKUP_SEMANTICS admits directories.
    // FSCTL_GET_REPARSE_POINT uses FILE_ANY_ACCESS, so no data access is needed.
    let raw = unsafe {
        ReOpenFile(
            file.as_handle().as_raw_handle() as HANDLE,
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
        )
    };
    owned_file(raw)
}

fn parse_reparse(bytes: &[u8]) -> io::Result<PathBuf> {
    let tag = u32_at(bytes, 0)?;
    let data_len = usize::from(u16_at(bytes, 4)?);
    let bytes = bytes
        .get(..8usize.checked_add(data_len).ok_or_else(invalid)?)
        .ok_or_else(invalid)?;
    let (base, relative) = match tag {
        IO_REPARSE_TAG_MOUNT_POINT => (16, false),
        IO_REPARSE_TAG_SYMLINK => {
            let flags = u32_at(bytes, 16)?;
            if flags > 1 {
                return Err(invalid());
            }
            (20, flags == 1)
        }
        _ => return Err(invalid()),
    };
    let offset = usize::from(u16_at(bytes, 8)?);
    let length = usize::from(u16_at(bytes, 10)?);
    if offset % 2 != 0 || length == 0 || length % 2 != 0 {
        return Err(invalid());
    }
    let start = base + offset;
    let target = bytes
        .get(start..start.checked_add(length).ok_or_else(invalid)?)
        .ok_or_else(invalid)?;
    let mut wide: Vec<u16> = target
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    if wide.contains(&0) {
        return Err(invalid());
    }
    if !relative {
        let prefix: Vec<u16> = "\\??\\".encode_utf16().collect();
        if !wide.starts_with(&prefix) {
            return Err(invalid());
        }
        wide.splice(..4, "\\\\?\\".encode_utf16());
    }
    Ok(PathBuf::from(OsString::from_wide(&wide)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::{query_mode_information, FileModeInformation};
    use std::{
        fs::{self, OpenOptions},
        os::windows::fs::{symlink_dir, symlink_file, OpenOptionsExt},
        path::Path,
        sync::atomic::{AtomicUsize, Ordering},
    };
    use windows_sys::Win32::{
        Foundation::ERROR_NOT_A_REPARSE_POINT, Storage::FileSystem::FILE_FLAG_OVERLAPPED,
    };

    // These tests run only on Windows (the crate is cfg(windows)). Successful
    // link queries additionally require the explicitly ignored native fixtures.
    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> io::Result<Self> {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            loop {
                let path = std::env::temp_dir().join(format!(
                    "winx-reparse-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed),
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Ok(Self(path)),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(error),
                }
            }
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn open_for_reparse(path: &Path, overlapped: bool) -> io::Result<File> {
        OpenOptions::new()
            .access_mode(0)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(
                FILE_FLAG_OPEN_REPARSE_POINT
                    | FILE_FLAG_BACKUP_SEMANTICS
                    | if overlapped { FILE_FLAG_OVERLAPPED } else { 0 },
            )
            .open(path)
    }

    #[test]
    fn read_reparse_target_reopens_synchronous_and_overlapped_handles() -> io::Result<()> {
        let directory = TestDirectory::new()?;
        let path = directory.0.join("ordinary file");
        fs::write(&path, b"ordinary data")?;
        let synchronous = FileModeInformation::FILE_SYNCHRONOUS_IO_ALERT
            | FileModeInformation::FILE_SYNCHRONOUS_IO_NONALERT;
        for overlapped in [false, true] {
            let file = open_for_reparse(&path, overlapped)?;
            let original_mode = query_mode_information(file.as_handle())?;
            assert_eq!(original_mode.intersects(synchronous), !overlapped);
            let reopened = synchronous_reparse_handle(&file)?;
            assert!(query_mode_information(reopened.as_handle())?.intersects(synchronous));
            assert_eq!(
                read_reparse_target(&file).unwrap_err().raw_os_error(),
                Some(ERROR_NOT_A_REPARSE_POINT as i32),
            );
            assert_eq!(query_mode_information(file.as_handle())?, original_mode);
        }
        Ok(())
    }

    #[test]
    #[ignore = "requires native Windows with symlink privilege or Developer Mode"]
    fn read_reparse_target_does_not_follow_file_or_directory_symlinks() -> io::Result<()> {
        for directory_link in [false, true] {
            let directory = TestDirectory::new()?;
            let path = directory.0.join("link");
            let target = Path::new("missing target with spaces");
            if directory_link {
                symlink_dir(target, &path)?;
            } else {
                symlink_file(target, &path)?;
            }
            // The target does not exist: following it cannot satisfy the query.
            for overlapped in [false, true] {
                let file = open_for_reparse(&path, overlapped)?;
                assert_eq!(read_reparse_target(&file)?, target);
            }
        }
        Ok(())
    }

    #[test]
    #[ignore = "requires native Windows with symlink privilege or Developer Mode"]
    fn read_reparse_target_keeps_the_held_object_after_name_replacement() -> io::Result<()> {
        for overlapped in [false, true] {
            let directory = TestDirectory::new()?;
            let path = directory.0.join("link");
            let moved = directory.0.join("moved link");
            let original = Path::new("original missing target");
            let replacement = Path::new("replacement missing target");
            symlink_file(original, &path)?;
            let held = open_for_reparse(&path, overlapped)?;
            fs::rename(&path, &moved)?;
            symlink_file(replacement, &path)?;
            assert_eq!(read_reparse_target(&held)?, original);
            assert_eq!(
                read_reparse_target(open_for_reparse(&path, overlapped)?)?,
                replacement,
            );
        }
        Ok(())
    }

    #[test]
    fn ordinary_unicode_names_survive_and_namespace_names_fail() {
        for name in ["設定 With Spaces", ".secret-ab.tmp", "header.value"] {
            assert!(check_name(OsStr::new(name)).is_ok());
        }
        for name in [
            "", ".", "..", "a/b", "a\\b", "x:stream", "a.", "a ", "CON", "nul.txt", "COM1", "LPT²",
            "x\0y",
        ] {
            assert!(check_name(OsStr::new(name)).is_err(), "{name:?}");
        }
    }

    #[test]
    fn reparse_ranges_are_bounded_before_decoding() {
        for len in 0..40 {
            assert!(parse_reparse(&vec![0; len]).is_err());
        }
        let mut bytes = vec![0; 24];
        bytes[..4].copy_from_slice(&IO_REPARSE_TAG_SYMLINK.to_le_bytes());
        bytes[4..6].copy_from_slice(&16u16.to_le_bytes());
        bytes[10..12].copy_from_slice(&4u16.to_le_bytes());
        bytes[16..20].copy_from_slice(&1u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&[b'a', 0, b'b', 0]);
        assert_eq!(parse_reparse(&bytes).unwrap(), PathBuf::from("ab"));
        bytes[8..10].copy_from_slice(&u16::MAX.to_le_bytes());
        assert!(parse_reparse(&bytes).is_err());
    }

    #[test]
    fn mounted_directory_target_preserves_unicode_and_spaces() {
        let target: Vec<u16> = r"\??\C:\Users\名前 With Spaces".encode_utf16().collect();
        let length = target.len() * 2;
        let mut bytes = vec![0; 16 + length];
        bytes[..4].copy_from_slice(&IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes());
        bytes[4..6].copy_from_slice(&((8 + length) as u16).to_le_bytes());
        bytes[10..12].copy_from_slice(&(length as u16).to_le_bytes());
        for (slot, value) in bytes[16..].chunks_exact_mut(2).zip(target) {
            slot.copy_from_slice(&value.to_le_bytes());
        }
        assert_eq!(
            parse_reparse(&bytes).unwrap(),
            PathBuf::from(r"\\?\C:\Users\名前 With Spaces")
        );
        for end in 0..bytes.len() {
            assert!(parse_reparse(&bytes[..end]).is_err());
        }
    }
}
