use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub game_path: String,
    pub auto_start: bool,
    pub auto_close: bool,
    pub popup_window: bool,
    pub fullscreen: bool,
    pub use_custom_res: bool,
    pub is_exclusive_fullscreen: bool,
    pub start_minimized: bool,
    pub use_power_save: bool,
    pub suspend_load: bool,
    pub use_mobile_ui: bool,
    pub fps_target: i32,
    pub custom_res_x: i32,
    pub custom_res_y: i32,
    pub monitor_num: i32,
    pub priority: i32,
    pub dll_list: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            game_path: String::from(""),
            auto_start: false,
            auto_close: false,
            popup_window: false,
            fullscreen: true,
            use_custom_res: false,
            is_exclusive_fullscreen: false,
            start_minimized: false,
            use_power_save: false,
            suspend_load: false,
            use_mobile_ui: false,
            fps_target: 120,
            custom_res_x: 1920,
            custom_res_y: 1080,
            monitor_num: 1,
            priority: 3,
            dll_list: Vec::new(),
        }
    }
}
