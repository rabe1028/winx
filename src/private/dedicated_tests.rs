use super::*;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        for _ in 0..64 {
            let path = std::env::temp_dir().join(format!(
                "winx-dedicated-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "fixture collisions",
        ))
    }

    fn open(&self) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .custom_flags(0x0200_0000 | 0x0020_0000)
            .open(&self.0)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn native_directory_dacl_changes_only_the_held_object_and_future_children() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let parent = fixture.open()?;
    let user = Sid::current_user()?;
    let everyone = Sid::from_parts(1, &[0])?;
    set_dacl_only(
        &parent,
        &SecurityTemplate::new(
            &user,
            &[(user.clone(), 0x1f01ff), (everyone, 0x120089)],
            true,
        )?,
    )?;
    fs::write(fixture.0.join("existing"), b"unchanged")?;
    fs::create_dir(fixture.0.join("existing-directory"))?;
    let old = File::open(fixture.0.join("existing"))?;
    let old_directory = open_child(
        &parent,
        OsStr::new("existing-directory"),
        Kind::Directory,
        Access::Read,
    )?;
    let before = security_info(&old)?;
    let before_directory = security_info(&old_directory)?;
    let private = SecurityTemplate::new(&user, &[(user.clone(), 0x1f01ff)], true)?;
    let pin = pin_directory(&parent)?;
    set_dacl_only(&pin, &private)?;
    assert_eq!(security_info(&old)?, before);
    assert_eq!(security_info(&old_directory)?, before_directory);
    assert_eq!(fs::read(fixture.0.join("existing"))?, b"unchanged");
    let actual = security_info(&pin)?;
    assert!(actual.protected);
    assert_eq!(actual.owner, user);
    assert!(actual.dacl.unwrap().iter().all(|ace| ace.sid == user));
    fs::write(fixture.0.join("new"), b"private from creation")?;
    let new = File::open(fixture.0.join("new"))?;
    assert!(security_info(&new)?
        .dacl
        .unwrap()
        .iter()
        .all(|ace| ace.sid == user));
    Ok(())
}

#[test]
fn native_read_creation_pins_without_delete_conflict_and_allows_child_io() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let parent = fixture.open()?;
    let user = Sid::current_user()?;
    let template = SecurityTemplate::new(&user, &[(user.clone(), 0x1f01ff)], true)?;
    let created = create_directory_read(&parent, OsStr::new("held"), &template)?;
    let first = pin_directory(&created)?;
    let second = pin_directory(&first)?;
    drop(created);
    fs::write(fixture.0.join("held/child"), b"value")?;
    fs::remove_file(fixture.0.join("held/child"))?;
    assert!(fs::rename(fixture.0.join("held"), fixture.0.join("moved")).is_err());
    drop(first);
    assert!(fs::rename(fixture.0.join("held"), fixture.0.join("moved")).is_err());
    drop(second);
    fs::rename(fixture.0.join("held"), fixture.0.join("moved"))?;
    Ok(())
}

#[test]
#[ignore = "requires native Windows with symlink privilege or Developer Mode"]
fn native_pin_keeps_directory_alias_identity() -> io::Result<()> {
    let fixture = Fixture::new()?;
    fs::create_dir(fixture.0.join("target"))?;
    std::os::windows::fs::symlink_dir("target", fixture.0.join("alias"))?;
    let parent = fixture.open()?;
    let alias = open_child(&parent, OsStr::new("alias"), Kind::Any, Access::Read)?;
    let pin = pin_directory(&alias)?;
    drop(alias);
    assert_eq!(read_reparse_target(&pin)?, PathBuf::from("target"));
    assert!(fs::rename(fixture.0.join("alias"), fixture.0.join("moved")).is_err());
    drop(pin);
    fs::rename(fixture.0.join("alias"), fixture.0.join("moved"))?;
    Ok(())
}

#[test]
#[ignore = "requires native Windows with symlink privilege or Developer Mode"]
fn native_dacl_reopen_keeps_alias_and_target_security_separate() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let parent = fixture.open()?;
    let user = Sid::current_user()?;
    let broad = SecurityTemplate::new(
        &user,
        &[
            (user.clone(), 0x1f01ff),
            (Sid::from_parts(1, &[0])?, 0x120089),
        ],
        true,
    )?;
    set_dacl_only(&parent, &broad)?;
    fs::create_dir(fixture.0.join("target"))?;
    fs::write(fixture.0.join("target/child"), b"unchanged")?;
    std::os::windows::fs::symlink_dir("target", fixture.0.join("alias"))?;
    let target = open_child(&parent, OsStr::new("target"), Kind::Directory, Access::Read)?;
    let child = File::open(fixture.0.join("target/child"))?;
    let target_before = security_info(&target)?;
    let child_before = security_info(&child)?;
    let alias = open_child(&parent, OsStr::new("alias"), Kind::Any, Access::Read)?;
    let pin = pin_directory(&alias)?;
    let alias_before = security_info(&pin)?;
    let private = SecurityTemplate::new(&user, &[(user.clone(), 0x1f01ff)], true)?;
    set_dacl_only(&pin, &private)?;
    let alias_after = security_info(&pin)?;
    assert_ne!(alias_after, alias_before);
    assert!(alias_after.protected);
    assert_eq!(alias_after.owner, user);
    assert!(alias_after.dacl.unwrap().iter().all(|ace| ace.sid == user));
    assert_eq!(security_info(&target)?, target_before);
    assert_eq!(security_info(&child)?, child_before);
    assert_eq!(read_reparse_target(&pin)?, PathBuf::from("target"));
    assert_eq!(fs::read(fixture.0.join("target/child"))?, b"unchanged");
    Ok(())
}
