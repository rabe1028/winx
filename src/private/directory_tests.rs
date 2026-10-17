use super::*;
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OVERLAPPED;

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> io::Result<Self> {
        for _ in 0..64 {
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("winx-directory-{}-{id}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "fixture collisions",
        ))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}

fn open_directory(path: &Path, overlapped: bool) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(
            FILE_FLAG_BACKUP_SEMANTICS
                | FILE_FLAG_OPEN_REPARSE_POINT
                | if overlapped { FILE_FLAG_OVERLAPPED } else { 0 },
        )
        .open(path)
}

#[test]
fn native_record_layout_and_page_alignment() {
    let layout = record_layout();
    assert_eq!((layout.length, layout.name), (60, 104));
    assert_eq!(std::mem::align_of::<Page>(), 8);
}

#[test]
fn empty_directory_ends_and_regular_file_is_rejected() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let parent = open_directory(&fixture.0, false)?;
    let mut names = directory_names(&parent)?;
    assert!(names.next().is_none());
    assert!(names.next().is_none());
    let path = fixture.0.join("ordinary-file");
    fs::write(&path, [])?;
    assert!(directory_names(File::open(path)?).is_err());
    Ok(())
}

#[test]
fn repeated_and_overlapped_handles_have_independent_complete_enumerations() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let mut expected = BTreeSet::new();
    for index in 0..700 {
        let name = OsString::from(format!("entry-{index:04}-{}", "x".repeat(64)));
        fs::write(fixture.0.join(&name), [])?;
        expected.insert(name);
    }
    let unicode = OsString::from("space 日本語 'value'");
    fs::write(fixture.0.join(&unicode), [])?;
    expected.insert(unicode);
    for overlapped in [false, true] {
        let parent = open_directory(&fixture.0, overlapped)?;
        let mut first = directory_names(&parent)?;
        let mut second = directory_names(&parent)?;
        let mut a = BTreeSet::new();
        let mut b = BTreeSet::new();
        loop {
            let one = first.next().transpose()?;
            let two = second.next().transpose()?;
            if one.is_none() && two.is_none() {
                break;
            }
            if let Some(name) = one {
                assert!(a.insert(name));
            }
            if let Some(name) = two {
                assert!(b.insert(name));
            }
        }
        assert_eq!(a, expected);
        assert_eq!(b, expected);
        assert!(first.next().is_none());
        assert!(second.next().is_none());
    }
    Ok(())
}

#[test]
fn enumeration_remains_on_original_directory_after_path_replacement() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let path = fixture.0.join("held");
    fs::create_dir(&path)?;
    fs::write(path.join("original"), [])?;
    let parent = open_directory(&path, false)?;
    let before = directory_names(&parent)?;
    fs::rename(&path, fixture.0.join("moved"))?;
    fs::create_dir(&path)?;
    fs::write(path.join("replacement"), [])?;
    let expected = BTreeSet::from([OsString::from("original")]);
    assert_eq!(before.collect::<io::Result<BTreeSet<_>>>()?, expected);
    assert_eq!(
        directory_names(&parent)?.collect::<io::Result<BTreeSet<_>>>()?,
        expected
    );
    Ok(())
}
