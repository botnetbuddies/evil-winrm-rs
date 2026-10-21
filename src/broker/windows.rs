//! Prevent a detached child from retaining a redirected launcher's standard pipes.
use std::{ffi::c_void, io};
type Handle = *mut c_void;
const INHERIT: u32 = 1;
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetStdHandle(which: u32) -> Handle;
    fn GetHandleInformation(handle: Handle, flags: *mut u32) -> i32;
    fn SetHandleInformation(handle: Handle, mask: u32, flags: u32) -> i32;
}

pub(super) struct StandardHandleGuard(Vec<(Handle, u32)>);
impl StandardHandleGuard {
    /// Used only by the launcher, before it starts any sessions or other children.
    /// Command supplies fresh null/log handles for the daemon's actual stdio.
    pub(super) fn exclude_from_children() -> io::Result<Self> {
        let mut guard = Self(Vec::new());
        for which in [-10i32, -11, -12] {
            // SAFETY: Win32 supplies these process-owned handles; no ownership is
            // transferred, and invalid/unavailable standard handles are skipped.
            let handle = unsafe { GetStdHandle(which as u32) };
            let mut flags = 0;
            if unsafe { GetHandleInformation(handle, &mut flags) } != 0 && flags & INHERIT != 0 {
                // SAFETY: The handle was validated above and remains process-owned.
                if unsafe { SetHandleInformation(handle, INHERIT, 0) } == 0 {
                    return Err(io::Error::last_os_error());
                }
                guard.0.push((handle, flags));
            }
        }
        Ok(guard)
    }
}
impl Drop for StandardHandleGuard {
    fn drop(&mut self) {
        for &(handle, flags) in &self.0 {
            // SAFETY: Restore only the inheritance bit on the same borrowed handles.
            unsafe { SetHandleInformation(handle, INHERIT, flags & INHERIT) };
        }
    }
}
