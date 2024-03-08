use serde::{Deserialize, Serialize};
use std::cmp;
use std::fs;

use crate::models::config::Config;

#[derive(Serialize, Deserialize)]
pub struct ConfigService {
    pub config_name: String,
    pub config: Config,
}

impl ConfigService {
    pub fn new() -> Self {
        let mut config_service = ConfigService {
            config_name: "fps_config.json".to_string(),
            config: Config::default(),
        };
        config_service.load();
        config_service.sanitize();
        config_service
    }

    fn load(&mut self) {
        if !std::path::Path::new(&self.config_name).exists() {
            return;
        }

        let json = fs::read_to_string(&self.config_name).unwrap();
        self.config = serde_json::from_str(&json).unwrap();
    }

    fn sanitize(&mut self) {
        self.config.fps_target = cmp::min(cmp::max(self.config.fps_target, 1), 420);
        self.config.priority = cmp::min(cmp::max(self.config.priority, 0), 5);
        self.config.custom_res_x = cmp::min(cmp::max(self.config.custom_res_x, 200), 7680);
        self.config.custom_res_y = cmp::min(cmp::max(self.config.custom_res_y, 200), 4320);
        self.config.monitor_num = cmp::min(cmp::max(self.config.monitor_num, 1), 100);
    }

    pub fn save(&self) {
        let json = serde_json::to_string_pretty(&self.config).unwrap();
        fs::write(&self.config_name, json).unwrap();
    }
}
