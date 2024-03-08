use serde::ser::Error;
use std::ffi::CString;
use std::ffi::OsStr;
use std::iter::once;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;
use std::ptr::null_mut;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use winapi::shared::minwindef::DWORD;
use winapi::shared::windef::HWND;
use winapi::um::handleapi::CloseHandle;
use winapi::um::libloaderapi::LoadLibraryExW;
use winapi::um::memoryapi::ReadProcessMemory;
use winapi::um::processthreadsapi::{
    CreateProcessA, GetExitCodeProcess, ResumeThread, SetPriorityClass, PROCESS_INFORMATION,
    STARTUPINFOA,
};
use winapi::um::winnt::HANDLE;
use winapi::um::winnt::IMAGE_DOS_HEADER;
use winapi::um::winnt::IMAGE_NT_HEADERS;
use winapi::um::winuser::GetWindowThreadProcessId;
use windows::Win32::Foundation::GetLastError;
use windows::Win32::System::Threading::PROCESS_CREATION_FLAGS;

fn to_wstring(str: &str) -> Vec<u16> {
    OsStr::new(str).encode_wide().chain(once(0)).collect()
}

use super::config_service::ConfigService;
use super::process_util;
use super::process_util::{inject_dlls, pattern_scan};

pub unsafe extern "system" fn win_event_proc(
    h_win_event_hook: HWND,
    event_type: u32,
    hwnd: HWND,
    id_object: i32,
    id_child: i32,
    dw_event_thread: DWORD,
    dwms_event_time: DWORD,
    process_service: &ProcessService,
) {
    if event_type != 3 {
        return;
    }

    let mut pid: DWORD = 0;
    GetWindowThreadProcessId(hwnd, &mut pid);

    let game_in_foreground = (pid as i32) == process_service.game_pid;

    // self.apply_fps_limit();

    if !process_service.config_service.config.use_power_save {
        return;
    }

    let target_priority = if game_in_foreground {
        process_service.priority_class[process_service.config_service.config.priority as usize]
    } else {
        0x00000040
    };

    SetPriorityClass(
        process_service.game_handle.unwrap() as HANDLE,
        target_priority,
    );
}

pub struct ProcessService {
    event_callback:
        Option<unsafe extern "system" fn(HWND, u32, HWND, i32, i32, DWORD, DWORD, &ProcessService)>,
    priority_class: [u32; 6],
    cts: Arc<AtomicBool>,
    win_event_hook: Option<HWND>,
    game_handle: Option<HWND>,
    remote_unity_player: Option<HWND>,
    remote_user_assembly: Option<HWND>,
    game_pid: i32,
    game_in_foreground: bool,
    p_fps_value: Option<HWND>,
    config_service: ConfigService,
}

impl ProcessService {
    pub fn new(config_service: ConfigService) -> Self {
        Self {
            event_callback: Some(win_event_proc),
            priority_class: [
                0x00000100, 0x00000080, 0x00008000, 0x00000020, 0x00004000, 0x00000040,
            ],
            cts: Arc::new(AtomicBool::new(false)),
            win_event_hook: None,
            game_handle: None,
            remote_unity_player: None,
            remote_user_assembly: None,
            game_pid: 0,
            game_in_foreground: true,
            p_fps_value: None,
            config_service,
        }
    }

    pub fn is_game_running(&self) -> bool {
        if self.game_handle.is_none() {
            return false;
        }

        let mut exit_code: DWORD = 0;
        unsafe {
            GetExitCodeProcess(self.game_handle.unwrap() as HANDLE, &mut exit_code);
        }

        exit_code == 259
    }

    pub async fn update_remote_modules(&mut self) -> Result<bool, Box<dyn Error>> {
        let mut retries = 0;

        loop {
            self.remote_unity_player =
                process_util::get_module_base(self.game_handle, "UnityPlayer.dll");
            self.remote_user_assembly =
                process_util::get_module_base(self.game_handle, "UserAssembly.dll");

            if !self.remote_unity_player.is_none() && !self.remote_user_assembly.is_none() {
                break;
            }

            if retries > 10 {
                break;
            }

            sleep(Duration::from_secs(2)).await;
            retries += 1;
        }

        if self.remote_unity_player.is_null() || self.remote_user_assembly.is_null() {
            // Handle the error here. Rust doesn't have a built-in MessageBox.
            return Err("Failed to get remote module base address".into());
        }

        Ok(true)
    }

    pub unsafe fn setup_data(&mut self) -> bool {
        let game_dir = Path::new(&self.config_service.config.game_path)
            .parent()
            .unwrap();
        let game_name = Path::new(&self.config_service.config.game_path)
            .file_stem()
            .unwrap();
        let data_dir = game_dir.join(format!("{}_Data", game_name.to_str().unwrap()));

        let unity_player_path = game_dir.join("UnityPlayer.dll");
        let user_assembly_path = data_dir.join("Native").join("UserAssembly.dll");

        let p_unity_player = unsafe {
            LoadLibraryExW(
                to_wstring(unity_player_path.to_str().unwrap()).as_ptr(),
                null_mut(),
                0,
            )
        };
        let p_user_assembly = unsafe {
            LoadLibraryExW(
                to_wstring(user_assembly_path.to_str().unwrap()).as_ptr(),
                null_mut(),
                0,
            )
        };

        if p_unity_player.is_null() || p_user_assembly.is_null() {
            panic!("Failed to load UnityPlayer.dll or UserAssembly.dll");
        }

        let dos_header = ptr::read(p_unity_player as *const IMAGE_DOS_HEADER);
        let nt_header = ptr::read(
            p_unity_player.offset(dos_header.e_lfanew as isize) as *const IMAGE_NT_HEADERS
        );

        if nt_header.FileHeader.TimeDateStamp < 0x656FFAF7 {
            // < 3.7
            let address_option = pattern_scan(p_unity_player as *mut u8, "7F 0F 8B 05 ? ? ? ?");
            if address_option.is_null() {
                panic!("Outdated FPS Pattern");
            };

            let address = address_option as *mut u32;
            let rip = address.offset(2);
            let rel = *rip;
            let local_va = rip.offset(rel as isize + 6);
            let remote_va = local_va.offset_from(p_unity_player as *mut u32) as u32;
            self.p_fps_value = Some(remote_va as HWND);
        } else {
            let mut rip: *mut u8 = std::ptr::null_mut();
            if nt_header.FileHeader.TimeDateStamp < 0x656FFAF7 {
                // < 4.3
                let address = pattern_scan(
                    p_user_assembly as *mut u8,
                    "E8 ? ? ? ? 85 C0 7E 07 E8 ? ? ? ? EB 05",
                );
                if address.is_null() {
                    panic!("BAD_PATTERN");
                }

                rip = address;
                rip = rip.offset(*(rip.offset(1) as *const i32) as isize + 5);
                rip = rip.offset(*(rip.offset(3) as *const i32) as isize + 7);
            } else {
                let address = pattern_scan(p_user_assembly as *mut u8, "B9 3C 00 00 00 FF 15");
                if address.is_null() {
                    panic!("BAD_PATTERN");
                }

                rip = address;
                rip = rip.offset(5);
                rip = rip.offset(*(rip.offset(2) as *const i32) as isize + 6);
            }

            let remote_va = rip.offset_from(p_user_assembly as *mut u8);
            let mut data_ptr: *mut u8 = std::ptr::null_mut();

            while data_ptr.is_null() {
                let mut read_result = [0u8; 8];
                ReadProcessMemory(
                    self.game_handle.unwrap() as HANDLE,
                    remote_va as *mut _,
                    &mut read_result as *mut _ as *mut _,
                    read_result.len(),
                    &mut 0,
                );

                let value = u64::from_ne_bytes(read_result);
                data_ptr = value as *mut u8;
            }

            let mut local_va =
                data_ptr.offset_from(self.remote_unity_player.unwrap() as *mut u8) as isize;
            while unsafe { *(local_va as *const u8) == 0xE8 || *(local_va as *const u8) == 0xE9 } {
                local_va = (local_va + *(local_va as *const i32) as isize + 5) as *mut u8 as isize;
            }

            local_va = (local_va as *mut u8).offset(*(local_va as *mut u8).offset(2) as isize + 6)
                as isize;
            let rva = (local_va as *mut u8).offset_from(p_unity_player as *mut u8);
            self.p_fps_value = Some((self.remote_unity_player.unwrap() as isize + rva) as HWND);
        }

        true
    }

    pub async fn worker(&mut self) {
        let mut si: STARTUPINFOA = unsafe { std::mem::zeroed() };
        let pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        let creation_flag: DWORD = if self.config_service.config.suspend_load {
            PROCESS_CREATION_FLAGS as DWORD
        } else {
            0
        };
        let game_folder = Path::new(&self.config_service.config.game_path)
            .parent()
            .unwrap()
            .to_str()
            .unwrap();

        let game_path = CString::new(self.config_service.config.game_path.clone()).unwrap();
        let command_line = CString::new(self.build_command_line()).unwrap();
        let game_folder = CString::new(game_folder).unwrap();

        let success = unsafe {
            CreateProcessA(
                game_path.as_ptr(),
                command_line.as_ptr() as *mut _,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                false as i32,
                creation_flag,
                std::ptr::null_mut(),
                game_folder.as_ptr(),
                &mut si,
                &mut std::mem::zeroed::<winapi::um::processthreadsapi::PROCESS_INFORMATION>(),
            )
        };

        if success == 0 {
            println!("CreateProcess failed ({:?})", unsafe { GetLastError() });
            return;
        }

        let dll_list = self.config_service.config.dll_list.clone(); // Clone the dll_list

        if !inject_dlls(pi.hProcess, dll_list) {
            // Use the cloned dll_list
            println!("Dll Injection failed ({:?})", unsafe { GetLastError() });
        }

        if self.config_service.config.suspend_load {
            unsafe { ResumeThread(pi.hThread) };
        }

        self.game_pid = pi.dwProcessId as i32;
        self.game_handle = Some(pi.hProcess as HWND);

        unsafe { CloseHandle(pi.hThread) };

        // if !self.update_remote_modules().await {
        //     return;
        // }

        // if !self.setup_data() {
        //     return;
        // }

        while self.is_game_running() && !self.cts.load(std::sync::atomic::Ordering::Relaxed) {
            // self.apply_fps_limit();
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }

        if !self.is_game_running() && self.config_service.config.auto_close {
            tokio::task::spawn(async {
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                std::process::exit(0);
            });
        }
    }

    fn build_command_line(&self) -> String {
        let mut command_line = format!("{}", self.config_service.config.game_path);
        if self.config_service.config.popup_window {
            command_line.push_str(" -popupwindow");
        }
        if self.config_service.config.use_custom_res {
            command_line.push_str(&format!(
                "-screen-width {} -screen-height {} ",
                self.config_service.config.custom_res_x, self.config_service.config.custom_res_y
            ));
        }

        command_line.push_str(&format!(
            "-screen-fullscreen {} ",
            if self.config_service.config.fullscreen {
                1
            } else {
                0
            }
        ));

        if self.config_service.config.fullscreen {
            command_line.push_str(&format!(
                "-window-mode {} ",
                if self.config_service.config.is_exclusive_fullscreen {
                    "exclusive"
                } else {
                    "borderless"
                }
            ));
        }

        if self.config_service.config.use_mobile_ui {
            command_line.push_str(
                "use_mobile_platform -is_cloud 1 -platform_type CLOUD_THIRD_PARTY_MOBILE ",
            );
        }

        command_line.push_str(&format!(
            "-monitor {} ",
            self.config_service.config.monitor_num
        ));
        command_line
    }
}
