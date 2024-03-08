use std::mem;
use std::mem::size_of;
use std::ptr;
use std::ptr::null_mut;
use widestring::U16CString;
use winapi::shared::minwindef::DWORD;
use winapi::shared::minwindef::HMODULE;
use winapi::shared::ntdef::LPWSTR;
use winapi::um::handleapi::CloseHandle;
use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryW};
use winapi::um::memoryapi::{VirtualAllocEx, VirtualFreeEx, WriteProcessMemory};
use winapi::um::processthreadsapi::CreateRemoteThread;
use winapi::um::psapi::{EnumProcessModules, GetModuleBaseNameW, GetModuleInformation, MODULEINFO};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winnt::MEM_RELEASE;
use winapi::um::winnt::{HANDLE, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS};
use windows::Win32::Foundation::GetLastError;

pub fn get_module_base(
    h_process: *mut winapi::ctypes::c_void,
    module_name: &str,
) -> *mut winapi::ctypes::c_void {
    let mut modules: [HMODULE; 1024] = [null_mut(); 1024];
    let mut bytes_needed: DWORD = 0;

    if unsafe {
        EnumProcessModules(
            h_process,
            modules.as_mut_ptr(),
            (modules.len() * size_of::<HMODULE>()) as DWORD,
            &mut bytes_needed,
        )
    } == 0
    {
        if unsafe { GetLastError() } != windows::Win32::Foundation::WIN32_ERROR(299) {
            return null_mut();
        }
    }

    for &module in modules.iter().filter(|&&x| x != null_mut()) {
        let mut module_name_w = U16CString::from_str(module_name).unwrap();
        if unsafe {
            GetModuleBaseNameW(
                h_process,
                module,
                module_name_w.as_ptr() as LPWSTR,
                module_name_w.len() as DWORD,
            )
        } == 0
        {
            continue;
        }

        if module_name_w.to_string_lossy() != module_name {
            continue;
        }

        let mut module_info: MODULEINFO = unsafe { mem::zeroed() };
        if unsafe {
            GetModuleInformation(
                h_process,
                module,
                &mut module_info,
                size_of::<MODULEINFO>() as DWORD,
            )
        } == 0
        {
            continue;
        }

        return module_info.lpBaseOfDll;
    }

    null_mut()
}

pub unsafe fn pattern_scan(module: *mut u8, signature: &str) -> *mut u8 {
    let tokens: Vec<&str> = signature.split(' ').collect();
    let pattern_bytes: Vec<u8> = tokens
        .iter()
        .map(|&x| {
            if x == "?" {
                0xFF
            } else {
                u8::from_str_radix(x, 16).unwrap()
            }
        })
        .collect();

    let dos_header = ptr::read(module as *const IMAGE_DOS_HEADER);
    let nt_header =
        ptr::read((module.offset(dos_header.e_lfanew as isize)) as *const IMAGE_NT_HEADERS);

    let size_of_image = nt_header.OptionalHeader.SizeOfImage;
    let scan_bytes = module;

    let s = pattern_bytes.len();
    let d = &pattern_bytes;

    for i in 0..size_of_image - s as DWORD {
        let mut found = true;
        for j in 0..s {
            if d[j] != *scan_bytes.offset((i + j as DWORD) as isize) && d[j] != 0xFF {
                found = false;
                break;
            }
        }

        if found {
            return module.offset(i as isize);
        }
    }

    ptr::null_mut()
}

pub fn inject_dlls(process_handle: HANDLE, dll_paths: Vec<String>) -> bool {
    if dll_paths.is_empty() {
        return true;
    }

    let kernel32 = unsafe { LoadLibraryW(U16CString::from_str("kernel32.dll").unwrap().as_ptr()) };
    let load_library = unsafe { GetProcAddress(kernel32, "LoadLibraryW\0".as_ptr() as *const i8) };

    let remote_va = unsafe {
        VirtualAllocEx(
            process_handle,
            null_mut(),
            0x1000,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if remote_va.is_null() {
        return false;
    }

    for dll_path in dll_paths {
        let native_string = U16CString::from_str(&dll_path).unwrap();
        let bytes = native_string.as_ustr_with_nul();

        let mut bytes_written: usize = 0;
        let write_result = unsafe {
            WriteProcessMemory(
                process_handle,
                remote_va,
                bytes.as_ptr() as *const _,
                bytes.len(),
                &mut bytes_written,
            )
        };
        if write_result == 0 {
            return false;
        }

        let thread = unsafe {
            CreateRemoteThread(
                process_handle,
                null_mut(),
                0,
                Some(std::mem::transmute(load_library)),
                remote_va,
                0,
                null_mut(),
            )
        };
        if thread.is_null() {
            return false;
        }

        unsafe { WaitForSingleObject(thread, u32::MAX) };
        unsafe { CloseHandle(thread) };
        unsafe {
            WriteProcessMemory(
                process_handle,
                remote_va,
                vec![0; bytes.len()].as_ptr() as *const _,
                bytes.len(),
                &mut bytes_written,
            )
        };
    }

    unsafe { VirtualFreeEx(process_handle, remote_va, 0, MEM_RELEASE) };

    true
}
