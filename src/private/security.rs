use super::{
    buffer::{u16_at, u32_at, Buffer},
    invalid,
};
use std::os::windows::io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle};
use std::{io, mem, ptr};
use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_NO_TOKEN, HANDLE};
use windows_sys::Win32::Security::Authorization::{SetSecurityInfo, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    GetKernelObjectSecurity, GetTokenInformation, TokenUser, DACL_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, SE_DACL_PRESENT,
    SE_DACL_PROTECTED, SE_SELF_RELATIVE, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
};

/// A validated, owned binary SID. Equality compares all identifier bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sid(Vec<u8>);

impl Sid {
    /// Construct a SID without resolving account names or using the environment.
    pub fn from_parts(authority: u64, subauthorities: &[u32]) -> io::Result<Self> {
        if authority >> 48 != 0 || subauthorities.len() > 15 {
            return Err(invalid());
        }
        let mut bytes = vec![1, subauthorities.len() as u8];
        bytes.extend_from_slice(&authority.to_be_bytes()[2..]);
        for value in subauthorities {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        Ok(Self(bytes))
    }

    /// Read the current process token user. Impersonation is explicitly rejected:
    /// a private-storage operation must run under one stable process identity.
    pub fn current_user() -> io::Result<Self> {
        let mut raw = HANDLE::default();
        // SAFETY: pseudo-handles are valid for these calls; output is an owned
        // token handle on success, immediately wrapped before any early return.
        if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) } != 0 {
            let _token = unsafe { OwnedHandle::from_raw_handle(raw as _) };
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private storage does not support impersonation",
            ));
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_NO_TOKEN as i32) {
            return Err(error);
        }
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = unsafe { OwnedHandle::from_raw_handle(raw as _) };
        let mut size = 0;
        // SAFETY: first call obtains a size; it cannot write through a null buffer.
        unsafe {
            GetTokenInformation(
                token.as_raw_handle() as HANDLE,
                TokenUser,
                ptr::null_mut(),
                0,
                &mut size,
            )
        };
        if io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
            return Err(io::Error::last_os_error());
        }
        let mut buffer = Buffer::new(size as usize)?;
        if unsafe {
            GetTokenInformation(
                token.as_raw_handle() as HANDLE,
                TokenUser,
                buffer.as_mut_ptr(),
                size,
                &mut size,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let bytes = buffer.bytes().get(..size as usize).ok_or_else(invalid)?;
        if bytes.len() < mem::size_of::<TOKEN_USER>() {
            return Err(invalid());
        }
        // SAFETY: the output buffer is initialized and pointer-aligned, and the
        // complete TOKEN_USER header was checked above. No SID is dereferenced.
        let user = unsafe { ptr::read(buffer.as_ptr().cast::<TOKEN_USER>()) };
        let offset = (user.User.Sid as usize)
            .checked_sub(buffer.as_ptr() as usize)
            .ok_or_else(invalid)?;
        Self::parse(bytes.get(offset..).ok_or_else(invalid)?)
    }

    fn parse(bytes: &[u8]) -> io::Result<Self> {
        if bytes.first() != Some(&1) {
            return Err(invalid());
        }
        let count = usize::from(*bytes.get(1).ok_or_else(invalid)?);
        if count > 15 {
            return Err(invalid());
        }
        let length = 8 + count * 4;
        Ok(Self(bytes.get(..length).ok_or_else(invalid)?.to_vec()))
    }
}

/// Only ordinary allow/deny ACEs are accepted. Object/callback/conditional ACEs
/// require a separate evaluator and are rejected rather than misinterpreted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AceKind {
    Allow,
    Deny,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ace {
    pub kind: AceKind,
    pub flags: u8,
    pub mask: u32,
    pub sid: Sid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityInfo {
    pub owner: Sid,
    /// None represents a missing or NULL DACL (unrestricted access).
    pub dacl: Option<Vec<Ace>>,
    pub protected: bool,
}

/// Retrieve owner and DACL from this exact handle, without pathname resolution.
pub fn security_info<H: AsHandle>(file: H) -> io::Result<SecurityInfo> {
    let handle = file.as_handle();
    let flags = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut size = 0;
    unsafe {
        GetKernelObjectSecurity(
            handle.as_raw_handle() as HANDLE,
            flags,
            ptr::null_mut(),
            0,
            &mut size,
        )
    };
    if io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
        return Err(io::Error::last_os_error());
    }
    // Another trusted writer may change the DACL size between calls. Bound both
    // allocation and retries. Untrusted writers are rejected by caller policy.
    for _ in 0..3 {
        let capacity = size;
        let mut buffer = Buffer::new(capacity as usize)?;
        let ok = unsafe {
            GetKernelObjectSecurity(
                handle.as_raw_handle() as HANDLE,
                flags,
                buffer.as_mut_ptr(),
                capacity,
                &mut size,
            )
        };
        if ok != 0 {
            return parse_security(buffer.bytes().get(..size as usize).ok_or_else(invalid)?);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
            return Err(error);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::WouldBlock,
        "security descriptor changed repeatedly",
    ))
}

fn parse_security(bytes: &[u8]) -> io::Result<SecurityInfo> {
    if bytes.len() < 20 || bytes[0] != 1 {
        return Err(invalid());
    }
    let control = u16_at(bytes, 2)?;
    if control & SE_SELF_RELATIVE == 0 {
        return Err(invalid());
    }
    let owner_offset = u32_at(bytes, 4)? as usize;
    if owner_offset < 20 || owner_offset % 4 != 0 {
        return Err(invalid());
    }
    let owner = Sid::parse(bytes.get(owner_offset..).ok_or_else(invalid)?)?;
    let dacl_offset = u32_at(bytes, 16)? as usize;
    let dacl = if control & SE_DACL_PRESENT == 0 || dacl_offset == 0 {
        None
    } else {
        if dacl_offset < 20 || dacl_offset % 4 != 0 {
            return Err(invalid());
        }
        Some(parse_acl(bytes.get(dacl_offset..).ok_or_else(invalid)?)?)
    };
    Ok(SecurityInfo {
        owner,
        dacl,
        protected: control & SE_DACL_PROTECTED != 0,
    })
}

fn parse_acl(bytes: &[u8]) -> io::Result<Vec<Ace>> {
    if !matches!(bytes.first(), Some(2 | 4)) || bytes.len() < 8 {
        return Err(invalid());
    }
    let size = usize::from(u16_at(bytes, 2)?);
    let count = usize::from(u16_at(bytes, 4)?);
    let bytes = bytes.get(..size).ok_or_else(invalid)?;
    if size < 8 || count > (size - 8) / 16 {
        return Err(invalid());
    }
    let mut entries = Vec::with_capacity(count);
    let mut offset = 8;
    for _ in 0..count {
        let ace_size = usize::from(u16_at(bytes, offset + 2)?);
        if ace_size < 16 || ace_size % 4 != 0 {
            return Err(invalid());
        }
        let ace = bytes
            .get(offset..offset.checked_add(ace_size).ok_or_else(invalid)?)
            .ok_or_else(invalid)?;
        if ace[1] & !0x1f != 0 {
            return Err(invalid());
        }
        let kind = match ace[0] {
            0 => AceKind::Allow,
            1 => AceKind::Deny,
            _ => return Err(invalid()),
        };
        let sid = Sid::parse(&ace[8..])?;
        if sid.0.len() != ace_size - 8 {
            return Err(invalid());
        }
        entries.push(Ace {
            kind,
            flags: ace[1],
            mask: u32_at(ace, 4)?,
            sid,
        });
        offset += ace_size;
    }
    Ok(entries)
}

/// Owned, self-relative protected security descriptor, supplied to the kernel
/// during creation. It has a non-null allow-list DACL, including when empty.
pub struct SecurityTemplate {
    buffer: Buffer,
    dacl_offset: usize,
}

impl SecurityTemplate {
    pub fn new(owner: &Sid, grants: &[(Sid, u32)], inherit: bool) -> io::Result<Self> {
        let dacl_offset = 20 + owner.0.len();
        let acl_length = grants.iter().try_fold(8usize, |n, (sid, _)| {
            n.checked_add(8 + sid.0.len()).ok_or_else(invalid)
        })?;
        let acl_length_u16 = u16::try_from(acl_length).map_err(|_| invalid())?;
        let count = u16::try_from(grants.len()).map_err(|_| invalid())?;
        let mut buffer = Buffer::new(dacl_offset.checked_add(acl_length).ok_or_else(invalid)?)?;
        let bytes = buffer.bytes_mut();
        bytes[0] = 1;
        bytes[2..4].copy_from_slice(
            &(SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_DACL_PROTECTED).to_le_bytes(),
        );
        bytes[4..8].copy_from_slice(&20u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&(dacl_offset as u32).to_le_bytes());
        bytes[20..dacl_offset].copy_from_slice(&owner.0);
        bytes[dacl_offset] = 2;
        bytes[dacl_offset + 2..dacl_offset + 4].copy_from_slice(&acl_length_u16.to_le_bytes());
        bytes[dacl_offset + 4..dacl_offset + 6].copy_from_slice(&count.to_le_bytes());
        let mut offset = dacl_offset + 8;
        for (sid, mask) in grants {
            let len = 8 + sid.0.len();
            bytes[offset + 1] = if inherit { 3 } else { 0 }; // OBJECT/CONTAINER_INHERIT_ACE
            bytes[offset + 2..offset + 4].copy_from_slice(&(len as u16).to_le_bytes());
            bytes[offset + 4..offset + 8].copy_from_slice(&mask.to_le_bytes());
            bytes[offset + 8..offset + len].copy_from_slice(&sid.0);
            offset += len;
        }
        Ok(Self {
            buffer,
            dacl_offset,
        })
    }

    pub(super) fn as_ptr(&self) -> *const std::ffi::c_void {
        self.buffer.as_ptr()
    }
}

/// Set only the protected DACL on the held object; never change its owner.
/// Callers must validate ownership/kind before requesting this mutation.
pub fn set_dacl<H: AsHandle>(file: H, template: &SecurityTemplate) -> io::Result<()> {
    let file = super::fs::reopen_for_dacl(file)?;
    // SAFETY: the descriptor constructor places an initialized ACL at a checked
    // four-byte-aligned offset, and it stays alive throughout SetSecurityInfo.
    let acl = unsafe {
        template
            .buffer
            .as_ptr()
            .cast::<u8>()
            .add(template.dacl_offset)
            .cast()
    };
    let result = unsafe {
        SetSecurityInfo(
            file.as_handle().as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            acl,
            ptr::null(),
        )
    };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    Ok(())
}

/// Set the protected DACL of this object without walking existing descendants.
/// Unlike SetSecurityInfo, this native object operation does not perform the
/// user-mode recursive inheritance update. Future children still inherit the
/// template's inheritable ACEs. Ownership is never changed.
pub fn set_dacl_only<H: AsHandle>(file: H, template: &SecurityTemplate) -> io::Result<()> {
    let file = super::fs::reopen_for_dacl(file)?;
    // SAFETY: the self-relative descriptor is initialized and correctly aligned,
    // remains alive throughout this synchronous call, and no pointer escapes.
    // The reopened handle requests WRITE_DAC on the same object.
    let result = unsafe {
        windows_sys::Wdk::Storage::FileSystem::NtSetSecurityObject(
            file.as_raw_handle() as HANDLE,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            template.as_ptr() as _,
        )
    };
    super::fs::nt_result(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_roundtrip_and_all_truncations() -> io::Result<()> {
        let sid = Sid::from_parts(5, &[21, 1, 2, 3, 1001])?;
        let template = SecurityTemplate::new(&sid, &[(sid.clone(), 0x1f01ff)], true)?;
        let parsed = parse_security(template.buffer.bytes())?;
        assert_eq!(parsed.owner, sid);
        assert!(parsed.protected);
        assert_eq!(parsed.dacl.as_ref().unwrap()[0].mask, 0x1f01ff);
        for end in 0..template.buffer.bytes().len() {
            assert!(parse_security(&template.buffer.bytes()[..end]).is_err());
        }
        Ok(())
    }

    #[test]
    fn null_empty_and_unknown_aces_are_distinct() -> io::Result<()> {
        let sid = Sid::from_parts(5, &[18])?;
        let mut template = SecurityTemplate::new(&sid, &[], false)?;
        assert!(parse_security(template.buffer.bytes())?
            .dacl
            .unwrap()
            .is_empty());
        template.buffer.bytes_mut()[16..20].fill(0);
        assert!(parse_security(template.buffer.bytes())?.dacl.is_none());
        let mut template = SecurityTemplate::new(&sid, &[(sid.clone(), 1)], false)?;
        template.buffer.bytes_mut()[template.dacl_offset + 8] = 9;
        assert!(parse_security(template.buffer.bytes()).is_err());
        Ok(())
    }
}
