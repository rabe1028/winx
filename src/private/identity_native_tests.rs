use super::super::{
    open_child, remove, security_info, set_dacl, set_dacl_only, Access, AceKind, Kind,
    SecurityInfo, SecurityTemplate, Sid,
};
use super::{identity, reopen_by_id};
use std::fs::{self, File, OpenOptions};
use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{io, mem, ptr};
use windows_sys::Win32::Foundation::{ERROR_SHARING_VIOLATION, HANDLE};
use windows_sys::Win32::Security::{GetTokenInformation, TokenIntegrityLevel, TOKEN_QUERY};
use windows_sys::Win32::Storage::FileSystem::{
    FileStandardInfo, GetFileInformationByHandleEx, ReOpenFile, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO, READ_CONTROL, SYNCHRONIZE, WRITE_DAC,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const FULL_ACCESS: u32 = 0x001f_01ff;
const INHERITED_ACE: u8 = 0x10;
const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

type Setter = fn(&File, &SecurityTemplate) -> io::Result<()>;

/// Production DACL setters that reopen through `reopen_for_dacl`, and whether
/// each documents propagation of inheritable ACEs to existing children.
const SETTERS: &[(&str, Setter, bool)] = &[
    ("set_dacl", |file, template| set_dacl(file, template), true),
    // NtSetSecurityObject on the object only; descendants are not walked.
    (
        "set_dacl_only",
        |file, template| set_dacl_only(file, template),
        false,
    ),
];

/// A uniquely named directory under the process temp directory. The parent is
/// opened through its path, so path aliases above it do not affect the test.
/// Drop removes the tree even when an assertion unwinds.
struct Fixture {
    root: PathBuf,
    handle: Option<File>,
}

impl Fixture {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        loop {
            let root = std::env::temp_dir().join(format!(
                "winx-dacl-by-id-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            match fs::create_dir(&root) {
                Ok(()) => {
                    let mut fixture = Self { root, handle: None };
                    fixture.handle = Some(win32_read_handle(&fixture.root)?);
                    return Ok(fixture);
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
    }

    fn handle(&self) -> io::Result<&File> {
        self.handle.as_ref().ok_or_else(super::super::invalid)
    }

    /// Create a directory with one file inside and a sibling file, all with
    /// the DACL inherited from the temp directory (not protected).
    fn objects(&self, tag: &str) -> io::Result<(String, String)> {
        let directory = format!("{tag}-dir");
        let file = format!("{tag}-file");
        fs::create_dir(self.root.join(&directory))?;
        fs::write(self.root.join(&directory).join("child"), b"child")?;
        fs::write(self.root.join(&file), b"file")?;
        Ok((directory, file))
    }

    fn open(&self, name: &str, kind: Kind, access: Access) -> io::Result<File> {
        open_child(self.handle()?, name.as_ref(), kind, access)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        drop(self.handle.take());
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// The access an ordinary adapter read handle carries, opened by CreateFileW.
fn win32_read_handle(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_READ_DATA | SYNCHRONIZE)
        .share_mode(SHARE_ALL)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

fn template() -> io::Result<(Sid, SecurityTemplate)> {
    let user = Sid::current_user()?;
    let template = SecurityTemplate::new(&user, &[(user.clone(), FULL_ACCESS)], true)?;
    Ok((user, template))
}

fn only_template_aces(info: &SecurityInfo, user: &Sid, inherited: bool) -> bool {
    info.dacl.as_ref().is_some_and(|aces| {
        !aces.is_empty()
            && aces.iter().all(|ace| {
                ace.kind == AceKind::Allow
                    && ace.sid == *user
                    && ace.mask == FULL_ACCESS
                    && (ace.flags & INHERITED_ACE != 0) == inherited
            })
    })
}

// Native: objects with an inherited, unprotected DACL are held only by
// NtCreateFile read handles (as the adapter holds admitted objects). Every
// production setter must replace that DACL with the protected template while
// keeping the owner and the held object's identity.
#[test]
fn unprotected_objects_receive_the_template_through_read_handles() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let (user, template) = template()?;
    for &(setter_name, setter, propagates) in SETTERS {
        let (directory_name, file_name) = fixture.objects(setter_name)?;
        let directory = fixture.open(&directory_name, Kind::Directory, Access::Read)?;
        let file = fixture.open(&file_name, Kind::File, Access::Read)?;
        let child = open_child(&directory, "child".as_ref(), Kind::File, Access::Read)?;
        let child_before = security_info(&child)?;
        for held in [&directory, &file] {
            let before = security_info(held)?;
            assert!(
                !before.protected,
                "{setter_name}: fixture must start unprotected"
            );
            assert!(
                !only_template_aces(&before, &user, false),
                "{setter_name}: already normalized"
            );
            let object = identity(held)?;
            setter(held, &template)?;
            let after = security_info(held)?;
            assert!(after.protected, "{setter_name}: DACL not protected");
            assert!(
                only_template_aces(&after, &user, false),
                "{setter_name}: {after:?}"
            );
            assert_eq!(after.owner, before.owner, "{setter_name}: owner changed");
            assert_eq!(
                identity(held)?,
                object,
                "{setter_name}: held identity changed"
            );
        }
        let child_after = security_info(&child)?;
        if propagates {
            // SetSecurityInfo documents propagation of inheritable ACEs to
            // existing children; the child now inherits only the template ACE.
            assert!(
                only_template_aces(&child_after, &user, true),
                "{setter_name}: child {child_after:?}"
            );
        } else {
            assert_eq!(
                child_after, child_before,
                "{setter_name}: descendants changed"
            );
        }
    }
    Ok(())
}

// Native: the reopen requests no DELETE access and shares read, write and
// delete, so it must coexist with an adapter handle holding DELETE and with a
// pin that denies delete sharing. The pin is checked to be effective first.
#[test]
fn dacl_updates_coexist_with_delete_handles_and_delete_denying_pins() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let (_, template) = template()?;
    for &(setter_name, setter, _) in SETTERS {
        let (directory_name, file_name) = fixture.objects(&format!("pin-{setter_name}"))?;
        for (name, kind) in [(&directory_name, Kind::Directory), (&file_name, Kind::File)] {
            let held = fixture.open(name, kind, Access::Read)?;
            {
                let _delete = fixture.open(name, kind, Access::Manage)?;
                setter(&held, &template)?;
            }
            // Share access is recorded only for data or DELETE access, so the pin
            // requests FILE_READ_DATA (FILE_LIST_DIRECTORY), as pin_directory does;
            // without it the missing FILE_SHARE_DELETE would not be enforced.
            let _pin = OpenOptions::new()
                .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_READ_DATA | SYNCHRONIZE)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .open(fixture.root.join(name))?;
            assert_eq!(
                fixture
                    .open(name, kind, Access::Manage)
                    .map(drop)
                    .unwrap_err()
                    .raw_os_error(),
                Some(ERROR_SHARING_VIOLATION as i32),
                "{setter_name}: pin does not deny DELETE",
            );
            setter(&held, &template)?;
        }
    }
    Ok(())
}

// Native: an object marked for deletion is refused before any DACL mutation.
#[test]
fn pending_deletion_fails_closed_before_reopen() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let (_, template) = template()?;
    for &(setter_name, setter, _) in SETTERS {
        let (_, file_name) = fixture.objects(&format!("pending-{setter_name}"))?;
        let held = fixture.open(&file_name, Kind::File, Access::Read)?;
        let before = security_info(&held)?;
        let deleting = fixture.open(&file_name, Kind::File, Access::Manage)?;
        remove(&deleting)?;
        let error = setter(&held, &template).unwrap_err();
        // Admission refuses before OpenFileById, which would otherwise also
        // report ERROR_ACCESS_DENIED; only the admission error has no OS code.
        assert_eq!(
            error.kind(),
            io::ErrorKind::PermissionDenied,
            "{setter_name}"
        );
        assert_eq!(error.raw_os_error(), None, "{setter_name}: {error}");
        assert_eq!(security_info(&held)?, before, "{setter_name}: DACL changed");
    }
    Ok(())
}

fn outcome(result: io::Result<File>) -> String {
    match result {
        Ok(_) => "ok".into(),
        Err(error) => format!(
            "error raw={:?} kind={:?}",
            error.raw_os_error(),
            error.kind()
        ),
    }
}

fn reopen_file(file: &File, access: u32) -> io::Result<File> {
    // SAFETY: borrows a live handle; a successful result is owned exactly once.
    let raw = unsafe {
        ReOpenFile(
            file.as_raw_handle() as HANDLE,
            access,
            SHARE_ALL,
            FILE_FLAG_BACKUP_SEMANTICS,
        )
    };
    super::super::fs::owned_file(raw)
}

fn delete_pending(file: &File) -> io::Result<bool> {
    let mut info = mem::MaybeUninit::<FILE_STANDARD_INFO>::zeroed();
    // SAFETY: the buffer is the documented, correctly sized FileStandardInfo output.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle() as HANDLE,
            FileStandardInfo,
            info.as_mut_ptr().cast(),
            mem::size_of::<FILE_STANDARD_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: initialized by the successful query above.
    Ok(unsafe { info.assume_init() }.DeletePending != 0)
}

/// The process token's mandatory integrity RID (for example 0x2000 medium,
/// 0x3000 high, 0x4000 system). Diagnostic only.
fn process_integrity_rid() -> io::Result<u32> {
    let mut raw = HANDLE::default();
    // SAFETY: pseudo-handle input; the token handle is owned immediately.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful call above returned one owned token handle.
    let token = unsafe {
        <std::os::windows::io::OwnedHandle as std::os::windows::io::FromRawHandle>::from_raw_handle(
            raw as _,
        )
    };
    let mut buffer = [0usize; 16];
    let mut size = 0;
    // SAFETY: the pointer-aligned buffer and its byte length are valid.
    let ok = unsafe {
        GetTokenInformation(
            token.as_raw_handle() as HANDLE,
            TokenIntegrityLevel,
            buffer.as_mut_ptr().cast(),
            mem::size_of_val(&buffer) as u32,
            &mut size,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // TOKEN_MANDATORY_LABEL starts with a SID pointer into this same buffer.
    let start = buffer.as_ptr() as usize;
    let end = start + size as usize;
    let sid = buffer[0];
    if sid < start || sid + 8 > end {
        return Err(super::super::invalid());
    }
    // SAFETY: the SID header lies within the initialized token buffer.
    let count = usize::from(unsafe { ptr::read((sid + 1) as *const u8) });
    let rid = sid + 8 + count.checked_sub(1).ok_or_else(super::super::invalid)? * 4;
    if rid + 4 > end {
        return Err(super::super::invalid());
    }
    // SAFETY: bounds were checked against the bytes Windows reported.
    Ok(unsafe { ptr::read_unaligned(rid as *const u32) })
}

// Native diagnostic for the unresolved access-denied report: record whether
// ReOpenFile and the identity reopen succeed on NtCreateFile and CreateFileW
// read handles. It asserts only fixture setup, never an expected cause; run
// with `-- --ignored --nocapture` and keep the printed outcomes as evidence.
#[test]
#[ignore = "native diagnostic: prints reopen A/B outcomes for acceptance records"]
fn diagnose_reopen_outcomes_by_handle_origin() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let (directory_name, file_name) = fixture.objects("diagnostic")?;
    eprintln!("process integrity RID: {:?}", process_integrity_rid());
    let requests = [
        (
            "ReOpenFile FILE_READ_ATTRIBUTES",
            FILE_READ_ATTRIBUTES,
            false,
        ),
        ("ReOpenFile READ_CONTROL", READ_CONTROL, false),
        (
            "ReOpenFile READ_CONTROL|WRITE_DAC",
            READ_CONTROL | WRITE_DAC,
            false,
        ),
        (
            "OpenFileById READ_CONTROL|WRITE_DAC",
            READ_CONTROL | WRITE_DAC,
            true,
        ),
    ];
    for (name, kind) in [(&directory_name, Kind::Directory), (&file_name, Kind::File)] {
        let origins = [
            ("NtCreateFile", fixture.open(name, kind, Access::Read)?),
            ("CreateFileW", win32_read_handle(&fixture.root.join(name))?),
        ];
        for (origin, held) in &origins {
            eprintln!(
                "{kind:?} via {origin}: delete pending {:?}, protected {:?}",
                delete_pending(held),
                security_info(held).map(|info| info.protected),
            );
            for (label, access, by_id) in requests {
                let result = if by_id {
                    reopen_by_id(held, access)
                } else {
                    reopen_file(held, access)
                };
                eprintln!("  {label}: {}", outcome(result));
            }
        }
    }
    Ok(())
}
