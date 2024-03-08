extern crate winapi;

use std::ffi::OsStr;
use std::iter::once;
use std::os::raw::c_void;
use std::os::windows::ffi::OsStrExt;
use winapi::shared::minwindef::{DWORD, HMODULE, LPARAM, UINT};
use winapi::shared::ntdef::{PVOID, WCHAR};
use winapi::shared::windef::{self, HWINEVENTHOOK, HWND};
use winapi::um::winuser::{
    EnumWindows, FindWindowW, GetClassNameW, GetWindowThreadProcessId, SetWinEventHook,
    UnhookWinEvent,
};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{self};
use windows::Win32::Security;
use windows::Win32::System::Memory::{VirtualFreeEx, VIRTUAL_FREE_TYPE};
use windows::Win32::System::Threading::{
    CreateMutexW, CreateProcessW, CreateRemoteThread, GetExitCodeProcess, OpenProcess,
    QueryFullProcessImageNameW, ResumeThread, TerminateProcess, PROCESS_CREATION_FLAGS,
};

use windows::Win32::System::Diagnostics::Debug::{
    ReadProcessMemory, WaitForDebugEvent, WriteProcessMemory,
};

type EnumWindowProc = extern "system" fn(
    hWnd: winapi::shared::windef::HWND,
    lParam: winapi::shared::minwindef::LPARAM,
) -> winapi::shared::minwindef::BOOL;

pub type WinEventProc = unsafe extern "system" fn(
    hWinEventHook: winapi::shared::windef::HWINEVENTHOOK,
    eventType: winapi::shared::minwindef::DWORD,
    hwnd: windef::HWND,
    idObject: winapi::ctypes::c_int,
    idChild: winapi::ctypes::c_int,
    dwEventThread: winapi::shared::minwindef::DWORD,
    dwmsEventTime: winapi::shared::minwindef::DWORD,
);

pub struct WindowsNative {}

impl WindowsNative {
    pub fn find_window(class_name: &str, window_name: &str) -> winapi::shared::windef::HWND {
        let class_name: Vec<u16> = OsStr::new(class_name)
            .encode_wide()
            .chain(once(0))
            .collect();

        let window_name: Vec<u16> = OsStr::new(window_name)
            .encode_wide()
            .chain(once(0))
            .collect();

        unsafe { FindWindowW(class_name.as_ptr(), window_name.as_ptr()) }
    }

    pub fn enum_windows(enum_func: EnumWindowProc, l_param: LPARAM) -> bool {
        unsafe { EnumWindows(Some(enum_func), l_param) != 0 }
    }

    pub fn get_class_name(hwnd: HWND, lp_class_name: &mut [WCHAR], n_max_count: i32) -> i32 {
        unsafe { GetClassNameW(hwnd, lp_class_name.as_mut_ptr(), n_max_count) }
    }

    pub fn set_win_event_hook(
        event_min: DWORD,
        event_max: DWORD,
        hmod_win_event_proc: HMODULE,
        lpfn_win_event_proc: Option<WinEventProc>,
        id_process: DWORD,
        id_thread: DWORD,
        dw_flags: DWORD,
    ) -> windef::HWINEVENTHOOK {
        unsafe {
            SetWinEventHook(
                event_min,
                event_max,
                hmod_win_event_proc,
                lpfn_win_event_proc,
                id_process,
                id_thread,
                dw_flags,
            )
        }
    }

    pub fn unhook_win_event(h_win_event_hook: HWINEVENTHOOK) -> bool {
        unsafe { UnhookWinEvent(h_win_event_hook) != 0 }
    }

    pub fn get_window_thread_process_id(hwnd: HWND, ldpw_process_id: &mut DWORD) -> DWORD {
        unsafe { GetWindowThreadProcessId(hwnd, ldpw_process_id) }
    }

    pub fn create_mutex(
        lp_mutex_attributes: Option<*const Security::SECURITY_ATTRIBUTES>,
        b_initial_owner: bool,
        lp_name: &str,
    ) -> Result<windows::Win32::Foundation::HANDLE, windows::core::Error> {
        let mut lp_name: Vec<u16> = OsStr::new(lp_name).encode_wide().chain(once(0)).collect();
        unsafe {
            CreateMutexW(
                lp_mutex_attributes,
                b_initial_owner,
                PCWSTR(lp_name.as_mut_ptr()),
            )
        }
    }

    pub fn open_process(
        dw_desired_access: DWORD,
        b_inherit_handle: bool,
        dw_process_id: DWORD,
    ) -> Result<Foundation::HANDLE, windows::core::Error> {
        unsafe {
            OpenProcess(
                windows::Win32::System::Threading::PROCESS_ACCESS_RIGHTS(dw_desired_access),
                b_inherit_handle,
                dw_process_id,
            )
        }
    }

    pub fn close_handle(h_handle: Foundation::HANDLE) -> Result<(), windows::core::Error> {
        unsafe { Foundation::CloseHandle(h_handle) }
    }

    pub fn terminate_process(
        h_process: Foundation::HANDLE,
        u_exit_code: UINT,
    ) -> Result<(), windows::core::Error> {
        unsafe { TerminateProcess(h_process, u_exit_code) }
    }

    pub fn query_full_process_image_name(
        h_process: Foundation::HANDLE,
        dw_flags: u32,
        lp_exe_name: PWSTR,
        ldpw_size: &mut u32,
    ) -> Result<(), windows::core::Error> {
        unsafe {
            QueryFullProcessImageNameW(
                h_process,
                windows::Win32::System::Threading::PROCESS_NAME_FORMAT(dw_flags),
                lp_exe_name,
                ldpw_size,
            )
        }
    }

    pub fn get_exit_code_process(
        h_process: Foundation::HANDLE,
        lp_exit_code: &mut DWORD,
    ) -> Result<(), windows::core::Error> {
        unsafe { GetExitCodeProcess(h_process, lp_exit_code) }
    }

    pub fn create_process(
        lp_application_name: &str,
        lp_command_line: &str,
        lp_process_attributes: Option<*const Security::SECURITY_ATTRIBUTES>,
        lp_thread_attributes: Option<*const Security::SECURITY_ATTRIBUTES>,
        b_inherit_handles: bool,
        dw_creation_flags: u32,
        lp_environment: Option<*const std::ffi::c_void>,
        lp_current_directory: &str,
        lp_startup_info: &mut windows::Win32::System::Threading::STARTUPINFOW,
        lp_process_information: &mut windows::Win32::System::Threading::PROCESS_INFORMATION,
    ) -> Result<(), windows::core::Error> {
        let mut lp_application_name: Vec<u16> = OsStr::new(lp_application_name)
            .encode_wide()
            .chain(once(0))
            .collect();
        let mut lp_command_line: Vec<u16> = OsStr::new(lp_command_line)
            .encode_wide()
            .chain(once(0))
            .collect();
        let mut lp_current_directory: Vec<u16> = OsStr::new(lp_current_directory)
            .encode_wide()
            .chain(once(0))
            .collect();
        unsafe {
            CreateProcessW(
                PCWSTR(lp_application_name.as_mut_ptr()),
                PWSTR(lp_command_line.as_mut_ptr()),
                lp_process_attributes,
                lp_thread_attributes,
                b_inherit_handles,
                PROCESS_CREATION_FLAGS(dw_creation_flags),
                lp_environment,
                PCWSTR(lp_current_directory.as_mut_ptr()),
                lp_startup_info,
                lp_process_information,
            )
        }
    }

    pub fn resume_thread(h_thread: Foundation::HANDLE) -> Result<u32, windows::core::Error> {
        unsafe { Ok(ResumeThread(h_thread)) }
    }

    pub fn write_process_memory(
        h_process: Foundation::HANDLE,
        lp_base_address: *mut std::ffi::c_void,
        lp_buffer: &[u8],
        n_size: usize,
        lp_number_of_bytes_written: Option<*mut usize>,
    ) -> Result<(), windows::core::Error> {
        unsafe {
            WriteProcessMemory(
                h_process,
                lp_base_address,
                lp_buffer.as_ptr() as *const std::ffi::c_void,
                n_size,
                lp_number_of_bytes_written,
            )
        }
    }

    pub fn read_process_memory(
        h_process: Foundation::HANDLE,
        lp_base_address: *const std::ffi::c_void,
        lp_buffer: &mut [u8],
        n_size: usize,
        lp_number_of_bytes_read: Option<*mut usize>,
    ) -> Result<(), windows::core::Error> {
        unsafe {
            ReadProcessMemory(
                h_process,
                lp_base_address,
                lp_buffer.as_mut_ptr() as *mut std::ffi::c_void,
                n_size,
                lp_number_of_bytes_read,
            )
        }
    }

    pub fn to_wstring(value: &str) -> Vec<u16> {
        OsStr::new(value).encode_wide().chain(once(0)).collect()
    }

    pub fn create_remote_thread(
        h_process: Foundation::HANDLE,
        lp_thread_attributes: Option<*const Security::SECURITY_ATTRIBUTES>,
        dw_stack_size: usize,
        lp_start_address: PVOID,
        lp_parameter: Option<*const std::ffi::c_void>,
        dw_creation_flags: DWORD,
        lp_thread_id: Option<*mut DWORD>,
    ) -> Result<Foundation::HANDLE, windows::core::Error> {
        unsafe {
            CreateRemoteThread(
                h_process,
                lp_thread_attributes,
                dw_stack_size,
                Some(std::mem::transmute(lp_start_address)),
                lp_parameter,
                dw_creation_flags,
                lp_thread_id,
            )
        }
    }

    pub fn virtual_free_ex(
        h_process: Foundation::HANDLE,
        lp_address: *mut c_void,
        dw_size: usize,
        dw_free_type: VIRTUAL_FREE_TYPE,
    ) -> Result<(), windows::core::Error> {
        unsafe { VirtualFreeEx(h_process, lp_address, dw_size, dw_free_type) }
    }
}
