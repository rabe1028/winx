use std::ffi::OsString;
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use windows_sys::Win32::Storage::FileSystem::GetTempPathW;

/// Query `GetTempPathW`, preserving its UTF-16 spelling and trailing separator.
///
/// This is the legacy Windows selector used by SQLite, not `GetTempPath2W`.
/// The result is only a path: it may be missing, linked, relative, or unsuitable
/// for private storage. Callers must validate it separately. This function does
/// not create or modify a directory, or change process configuration. A caller
/// relying on the selection remaining stable must prevent concurrent changes to
/// the process environment and any other temporary-directory selectors.
pub fn temporary_directory() -> io::Result<PathBuf> {
    const CAPACITY: usize = 32_768;
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(CAPACITY)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "temporary path allocation failed"))?;
    buffer.resize(CAPACITY, 0u16);
    // SAFETY: the exclusive initialized buffer contains CAPACITY writable UTF-16
    // units and remains live for this synchronous call. No pointers are retained.
    let length = unsafe { GetTempPathW(CAPACITY as u32, buffer.as_mut_ptr()) } as usize;
    if length == 0 {
        return Err(io::Error::last_os_error());
    }
    if length >= buffer.len() || buffer[length] != 0 || buffer[..length].contains(&0) {
        return Err(super::invalid());
    }
    Ok(PathBuf::from(OsString::from_wide(&buffer[..length])))
}

#[cfg(test)]
mod tests {
    use super::temporary_directory;
    use std::ffi::OsString;
    use std::process::Command;

    const EXPECTED: &str = "WINX_TEST_EXPECTED_TEMP_PATH";

    #[test]
    fn query_child() {
        let expected = match std::env::var_os(EXPECTED) {
            Some(expected) => expected,
            None => return,
        };
        let selected = temporary_directory().expect("native temporary path query");
        assert_eq!(selected.as_os_str(), expected);
        assert!(!selected.exists(), "query must not create its result");
    }

    #[test]
    fn query_preserves_startup_tmp_without_creating_it() {
        let base = std::env::temp_dir().join(format!(
            "winx-query-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        ));
        let selected = base.join("temporary space 日本語");
        assert!(!selected.exists());
        let mut expected = OsString::from(selected.as_os_str());
        expected.push("\\");
        let status = Command::new(std::env::current_exe().expect("test executable"))
            .args(["--exact", "private::temporary::tests::query_child"])
            .env("TMP", &selected)
            .env("TEMP", base.join("other"))
            .env(EXPECTED, expected)
            .status()
            .expect("run isolated selector query");
        assert!(status.success());
        assert!(!base.exists(), "query must not create any directory");
    }
}
