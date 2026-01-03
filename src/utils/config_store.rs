use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ConfigOverrides {
    pub webhook_url: Option<String>,
    pub slack_webhook: Option<String>,
    pub discord_webhook: Option<String>,
}

impl ConfigOverrides {
    pub fn load() -> Self {
        let path = overrides_path();
        if Path::new(&path).exists() {
            if let Ok(content) = fs::read_to_string(&path) {
                if let Ok(cfg) = serde_json::from_str::<ConfigOverrides>(&content) {
                    return cfg;
                }
            }
        }
        ConfigOverrides::default()
    }

    pub fn save(&self) -> Result<()> {
        let path = overrides_path();
        if let Some(parent) = Path::new(&path).parent() {
            fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_string_pretty(self)?;
        fs::write(path, data)?;
        Ok(())
    }
}

fn overrides_path() -> String {
    "data/config_overrides.json".to_string()
}
