use windows::core::PCWSTR;
use windows::Win32::System::Services::{
    CloseServiceHandle, ControlService, SERVICE_CONTROL_STOP, SERVICE_STATUS,
};
use windows::Win32::System::Services::{
    CreateServiceW, DeleteService, OpenSCManagerW, OpenServiceW, StartServiceW, SC_HANDLE,
    SC_MANAGER_CREATE_SERVICE, SERVICE_ALL_ACCESS, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
    SERVICE_KERNEL_DRIVER,
};

/// SCM lifecycle for loading a research driver as a kernel service.
///
/// Ownership model: if the service already existed before this process
/// ran, we must NOT delete it on exit. Only services this process
/// created are eligible for stop+delete cleanup. The `created_by_us`
/// flag returned by `install` carries that distinction and Drop honors
/// it.
pub struct DriverService {
    scm: SC_HANDLE,
    svc: SC_HANDLE,
    created_by_us: bool,
}

impl DriverService {
    /// Create (or attach to) the kernel service for `driver_path`.
    ///
    /// Returns `(DriverService, created_by_us)` where `created_by_us`
    /// is true only when this call actually registered the service.
    pub fn install(name: &str, driver_path: &str) -> Result<(Self, bool), String> {
        let scm = unsafe { OpenSCManagerW(None, None, SC_MANAGER_CREATE_SERVICE) }
            .map_err(|e| format!("OpenSCManager: {e}"))?;

        let name_w: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let disp_w: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let path_w: Vec<u16> = driver_path.encode_utf16().chain(Some(0)).collect();

        let existing = unsafe { OpenServiceW(scm, PCWSTR(name_w.as_ptr()), SERVICE_ALL_ACCESS) };
        if let Ok(svc) = existing {
            return Ok((
                Self {
                    scm,
                    svc,
                    created_by_us: false,
                },
                false,
            ));
        }

        let svc = unsafe {
            CreateServiceW(
                scm,
                PCWSTR(name_w.as_ptr()),
                PCWSTR(disp_w.as_ptr()),
                SERVICE_ALL_ACCESS,
                SERVICE_KERNEL_DRIVER,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                PCWSTR(path_w.as_ptr()),
                None,
                None,
                None,
                None,
                None,
            )
        }
        .map_err(|e| {
            let _ = unsafe { CloseServiceHandle(scm) };
            format!("CreateService: {e}")
        })?;

        Ok((
            Self {
                scm,
                svc,
                created_by_us: true,
            },
            true,
        ))
    }

    pub fn start(&self) -> Result<(), String> {
        unsafe { StartServiceW(self.svc, None) }.map_err(|e| format!("StartService: {e}"))
    }
}

impl Drop for DriverService {
    fn drop(&mut self) {
        if self.created_by_us {
            // We own this service registration. Stop and mark it for
            // deletion so the system returns to its prior state.
            let _ = unsafe {
                ControlService(
                    self.svc,
                    SERVICE_CONTROL_STOP,
                    &mut SERVICE_STATUS::default(),
                )
            };
            let _ = unsafe { DeleteService(self.svc) };
        }
        unsafe {
            let _ = CloseServiceHandle(self.svc);
            let _ = CloseServiceHandle(self.scm);
        }
    }
}
