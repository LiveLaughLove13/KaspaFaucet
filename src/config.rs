use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;

#[derive(Clone, Serialize, Deserialize)]
pub struct Config {
    pub kaspad_url: String,
    pub port: u16,
    pub faucet_private_key: String,
    pub amount_per_claim: u64,
    pub claim_interval_seconds: u64,
}

// Custom Debug implementation that redacts sensitive information
impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Completely redact private key for security - never log the actual key
        let redacted_key = if !self.faucet_private_key.is_empty() {
            // Show only that a key is present, not its value
            format!("***REDACTED ({} chars)***", self.faucet_private_key.len())
        } else {
            "".to_string()
        };

        f.debug_struct("Config")
            .field("kaspad_url", &self.kaspad_url)
            .field("port", &self.port)
            .field("faucet_private_key", &redacted_key)
            .field("amount_per_claim", &self.amount_per_claim)
            .field("claim_interval_seconds", &self.claim_interval_seconds)
            .finish()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            kaspad_url: "127.0.0.1:16110".to_string(),
            port: 3010,
            faucet_private_key: String::new(),
            amount_per_claim: 100_000_000, // 0.001 KAS in sompis
            claim_interval_seconds: 3600,  // 1 hour
        }
    }
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        let config_path = "faucet-config.toml";
        if !std::path::Path::new(config_path).exists() {
            let default = Config::default();
            let toml = toml::to_string_pretty(&default)?;
            fs::write(config_path, toml)?;
            anyhow::bail!(
                "Created default config at {}. Please edit and restart.",
                config_path
            );
        }

        let contents = fs::read_to_string(config_path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }
}
