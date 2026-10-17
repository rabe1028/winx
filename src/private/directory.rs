use super::{directory_records, invalid};
use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::iter::FusedIterator;
use std::os::windows::{
    ffi::OsStringExt,
    fs::MetadataExt,
    io::{AsHandle, AsRawHandle, FromRawHandle},
};
use std::ptr;
use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_FILES, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    FileIdBothDirectoryInfo, FileIdBothDirectoryRestartInfo, GetFileInformationByHandleEx,
    ReOpenFile, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_BOTH_DIR_INFO, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, SYNCHRONIZE,
};

const PAGE_BYTES: usize = 65_536;

// FILE_ID_BOTH_DIR_INFO requires eight-byte alignment, including on 32-bit Windows.
#[repr(align(8))]
struct Page([u8; PAGE_BYTES]);

/// Independent enumeration of a held directory. It owns one synchronous handle
/// and a bounded native page. A partial enumeration never collects the rest.
pub struct DirectoryNames {
    directory: File,
    page: Box<Page>,
    cursor: Option<usize>,
    first: bool,
    finished: bool,
}

/// Enumerate the object identified by `parent`, without reconstructing a path.
/// Each iterator has its own cursor. Dot entries are omitted; other names retain
/// their original UTF-16 spelling and still require admission before use.
pub fn directory_names<P: AsHandle>(parent: P) -> io::Result<DirectoryNames> {
    // SAFETY: ReOpenFile returns a new owned handle to the supplied live object.
    // Omitting OVERLAPPED makes every query complete before its buffer is used.
    let handle = unsafe {
        ReOpenFile(
            parent.as_handle().as_raw_handle() as _,
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    if handle == HANDLE::default() {
        return Err(invalid());
    }
    // SAFETY: the successful native call transferred this one new handle.
    let directory = unsafe { File::from_raw_handle(handle as _) };
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(invalid());
    }
    Ok(DirectoryNames {
        directory,
        page: Box::new(Page([0; PAGE_BYTES])),
        cursor: None,
        first: true,
        finished: false,
    })
}

fn record_layout() -> directory_records::Layout {
    // SAFETY: this Windows C structure contains only integer fields and arrays.
    let header: FILE_ID_BOTH_DIR_INFO = unsafe { std::mem::zeroed() };
    let start = ptr::addr_of!(header) as usize;
    directory_records::Layout {
        length: ptr::addr_of!(header.FileNameLength) as usize - start,
        name: ptr::addr_of!(header.FileName) as usize - start,
    }
}

impl DirectoryNames {
    fn refill(&mut self) -> io::Result<bool> {
        self.page.0.fill(0);
        let first = self.first;
        self.first = false;
        // SAFETY: the handle is synchronous and the initialized, eight-byte
        // aligned page stays alive and exclusive throughout the complete call.
        let ok = unsafe {
            GetFileInformationByHandleEx(
                self.directory.as_raw_handle() as _,
                if first {
                    FileIdBothDirectoryRestartInfo
                } else {
                    FileIdBothDirectoryInfo
                },
                self.page.0.as_mut_ptr().cast(),
                PAGE_BYTES as u32,
            )
        };
        if ok == 0 {
            let error = io::Error::last_os_error();
            let code = error.raw_os_error();
            // Some filesystems report NO_SUCH_FILE for an empty initial root
            // enumeration. It is not treated as EOF after a successful page.
            if code == Some(ERROR_NO_MORE_FILES as i32)
                || (first && code == Some(ERROR_FILE_NOT_FOUND as i32))
            {
                return Ok(false);
            }
            return Err(error);
        }
        self.cursor = Some(0);
        Ok(true)
    }

    fn next_name(&mut self) -> io::Result<Option<OsString>> {
        loop {
            if self.cursor.is_none() && !self.refill()? {
                return Ok(None);
            }
            let offset = self.cursor.ok_or_else(invalid)?;
            let bytes = self.page.0.get(offset..).ok_or_else(invalid)?;
            let record = directory_records::decode(bytes, record_layout())?;
            self.cursor = record.next.map(|next| offset + next);
            if record.name == [46] || record.name == [46, 46] {
                continue;
            }
            return Ok(Some(OsString::from_wide(&record.name)));
        }
    }
}

impl Iterator for DirectoryNames {
    type Item = io::Result<OsString>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        match self.next_name() {
            Ok(Some(name)) => Some(Ok(name)),
            Ok(None) => {
                self.finished = true;
                None
            }
            Err(error) => {
                self.finished = true;
                Some(Err(error))
            }
        }
    }
}

impl FusedIterator for DirectoryNames {}

#[cfg(test)]
#[path = "directory_tests.rs"]
mod tests;
