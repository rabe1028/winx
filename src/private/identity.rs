use super::fs::owned_file;
use std::os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle};
use std::{fs::File, io, mem, ptr};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Storage::FileSystem::{
    ExtendedFileIdType, FileBasicInfo, FileIdInfo, FileStandardInfo, GetFileInformationByHandleEx,
    OpenFileById, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_BASIC_INFO,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_128, FILE_ID_DESCRIPTOR,
    FILE_ID_DESCRIPTOR_0, FILE_ID_INFO, FILE_INFO_BY_HANDLE_CLASS, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO,
};

/// Identity of one open filesystem object: the full 64-bit volume serial, the
/// full 128-bit file identifier and the directory/reparse kind. Identifiers are
/// never truncated to the legacy 64-bit file index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ObjectIdentity {
    volume: u64,
    id: [u8; 16],
    directory: bool,
    reparse: bool,
}

/// Validate the metadata queried from one handle. A deletion-pending object is
/// rejected: its namespace entry is leaving, so it must not be normalized.
fn admit(
    id: &FILE_ID_INFO,
    attributes: u32,
    delete_pending: bool,
    directory: bool,
) -> io::Result<ObjectIdentity> {
    if delete_pending {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private storage object is pending deletion",
        ));
    }
    if (attributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
        return Err(super::invalid());
    }
    Ok(ObjectIdentity {
        volume: id.VolumeSerialNumber,
        id: id.FileId.Identifier,
        directory,
        reparse: attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0,
    })
}

/// Require that a reopened handle refers to the exact object the caller holds.
fn same_object(expected: ObjectIdentity, actual: ObjectIdentity) -> io::Result<()> {
    if expected != actual {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "reopened Windows object identity changed",
        ));
    }
    Ok(())
}

/// # Safety
/// `T` must be the plain-data structure Windows documents for `class`.
unsafe fn query<T>(file: BorrowedHandle<'_>, class: FILE_INFO_BY_HANDLE_CLASS) -> io::Result<T> {
    let mut value = mem::MaybeUninit::<T>::zeroed();
    // SAFETY: the zeroed buffer has the exact size and alignment of `T`, which the
    // caller pairs with `class`; it is only read after the call reports success.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle() as HANDLE,
            class,
            value.as_mut_ptr().cast(),
            mem::size_of::<T>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { value.assume_init() })
}

pub(super) fn identity<F: AsHandle>(file: F) -> io::Result<ObjectIdentity> {
    let file = file.as_handle();
    // SAFETY: each structure is the documented output type of its class.
    let id: FILE_ID_INFO = unsafe { query(file, FileIdInfo)? };
    let basic: FILE_BASIC_INFO = unsafe { query(file, FileBasicInfo)? };
    let standard: FILE_STANDARD_INFO = unsafe { query(file, FileStandardInfo)? };
    admit(
        &id,
        basic.FileAttributes,
        standard.DeletePending != 0,
        standard.Directory != 0,
    )
}

fn descriptor(identity: &ObjectIdentity) -> FILE_ID_DESCRIPTOR {
    // NtCreateFile documents FILE_OPEN_BY_FILE_ID 16-byte reference numbers for
    // both NTFS (the 8-byte number zero-padded) and ReFS (an unrelated 128-bit
    // number), so the exact FileIdInfo identifier is passed without selection.
    FILE_ID_DESCRIPTOR {
        dwSize: mem::size_of::<FILE_ID_DESCRIPTOR>() as u32,
        Type: ExtendedFileIdType,
        Anonymous: FILE_ID_DESCRIPTOR_0 {
            ExtendedFileId: FILE_ID_128 {
                Identifier: identity.id,
            },
        },
    }
}

/// Open another handle with `access` to the object referenced by `file`.
///
/// The caller's handle stays open throughout: it is the volume hint, so the
/// identifier is resolved on its volume, and it keeps the object (and any
/// delete-sharing pin) alive. No pathname is resolved. The returned handle is
/// accepted only when its volume, identifier and kind match the original;
/// unsupported filesystems, pending deletion and mismatches fail closed.
pub(super) fn reopen_by_id<F: AsHandle>(file: F, access: u32) -> io::Result<File> {
    let file = file.as_handle();
    let expected = identity(file)?;
    let descriptor = descriptor(&expected);
    // SAFETY: the descriptor lives through this synchronous call, security
    // attributes are null, and a successful handle has exactly one owner.
    let raw = unsafe {
        OpenFileById(
            file.as_raw_handle() as HANDLE,
            &descriptor,
            access | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        )
    };
    let reopened = owned_file(raw)?;
    same_object(expected, identity(&reopened)?)?;
    Ok(reopened)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(volume: u64, id: [u8; 16]) -> FILE_ID_INFO {
        FILE_ID_INFO {
            VolumeSerialNumber: volume,
            FileId: FILE_ID_128 { Identifier: id },
        }
    }

    #[test]
    fn admission_records_kind_and_rejects_pending_deletion() -> io::Result<()> {
        let id = info(7, [3; 16]);
        let directory = admit(&id, FILE_ATTRIBUTE_DIRECTORY, false, true)?;
        assert!(directory.directory && !directory.reparse);
        let link = admit(&id, FILE_ATTRIBUTE_REPARSE_POINT, false, false)?;
        assert!(!link.directory && link.reparse);
        assert_eq!(
            admit(&id, 0, true, false).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied,
        );
        assert!(admit(&id, FILE_ATTRIBUTE_DIRECTORY, false, false).is_err());
        assert!(admit(&id, 0, false, true).is_err());
        Ok(())
    }

    #[test]
    fn every_identity_component_must_match() -> io::Result<()> {
        let base = admit(&info(u64::MAX, [9; 16]), 0, false, false)?;
        same_object(base, base)?;
        let mut high = [9; 16];
        high[15] = 8; // differs only above the legacy 64-bit index
        let mut low = [9; 16];
        low[0] = 8;
        let changed = [
            admit(&info(u64::MAX, high), 0, false, false)?,
            admit(&info(u64::MAX, low), 0, false, false)?,
            admit(&info(u64::MAX >> 1, [9; 16]), 0, false, false)?,
            admit(
                &info(u64::MAX, [9; 16]),
                FILE_ATTRIBUTE_DIRECTORY,
                false,
                true,
            )?,
            admit(
                &info(u64::MAX, [9; 16]),
                FILE_ATTRIBUTE_REPARSE_POINT,
                false,
                false,
            )?,
        ];
        for actual in changed {
            assert_eq!(
                same_object(base, actual).unwrap_err().kind(),
                io::ErrorKind::InvalidData,
            );
        }
        Ok(())
    }

    // Native: normalize objects held only through read handles, as the private
    // storage adapter does after admitting an existing directory or file.
    #[test]
    fn read_only_held_objects_receive_a_protected_dacl() -> io::Result<()> {
        use super::super::{
            create_directory, create_file, open_child, open_root, security_info, set_dacl, Access,
            Kind, SecurityTemplate, Sid,
        };
        use std::os::windows::ffi::OsStrExt;
        let temp = std::env::temp_dir();
        let wide: Vec<u16> = temp.as_os_str().encode_wide().collect();
        let drive = u8::try_from(wide[0]).map_err(|_| super::super::invalid())?;
        let mut parent = open_root(drive)?;
        for component in temp.components().skip(2) {
            parent = open_child(
                &parent,
                component.as_os_str(),
                Kind::Directory,
                Access::Read,
            )?;
        }
        let user = Sid::current_user()?;
        let template = SecurityTemplate::new(&user, &[(user.clone(), 0x1f01ff)], true)?;
        let name = format!("winx-dacl-by-id-{}", std::process::id());
        let created = create_directory(&parent, name.as_ref(), &template)?;
        let child = create_file(&created, "file".as_ref(), &template)?;
        drop(child);
        let directory = open_child(&parent, name.as_ref(), Kind::Directory, Access::Read)?;
        let file = open_child(&directory, "file".as_ref(), Kind::File, Access::Read)?;
        let result = (|| {
            for held in [&directory, &file] {
                let before = identity(held)?;
                set_dacl(held, &template)?;
                let after = security_info(held)?;
                assert!(after.protected);
                assert_eq!(identity(held)?, before);
            }
            Ok(())
        })();
        let file = open_child(&directory, "file".as_ref(), Kind::File, Access::Manage)?;
        super::super::remove(&file)?;
        drop(file);
        drop(directory);
        super::super::remove(&created)?;
        result
    }

    #[test]
    fn descriptor_carries_the_full_extended_identifier() -> io::Result<()> {
        let mut id = [0; 16];
        for (index, byte) in id.iter_mut().enumerate() {
            *byte = index as u8 + 1;
        }
        let identity = admit(&info(1, id), 0, false, false)?;
        let descriptor = descriptor(&identity);
        assert_eq!(descriptor.dwSize, 24);
        assert_eq!(descriptor.Type, ExtendedFileIdType);
        // SAFETY: the union was written through ExtendedFileId.
        assert_eq!(
            unsafe { descriptor.Anonymous.ExtendedFileId.Identifier },
            id
        );
        Ok(())
    }
}
