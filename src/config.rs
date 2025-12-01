use serde::{Deserialize, Serialize};
use solana_commitment_config::CommitmentLevel;
use std::{env::home_dir, fs, path::PathBuf};

use crate::error::ScillaError;

pub const SCILLA_CONFIG_RELATIVE_PATH: &str = ".config/scilla.toml";

pub fn scilla_config_path() -> PathBuf {
    let mut path = home_dir().expect("Error getting home path");
    path.push(SCILLA_CONFIG_RELATIVE_PATH);
    path
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct ScillaConfig {
    pub rpc_url: String,
    pub commitment_level: CommitmentLevel,
    pub keypair_path: PathBuf,
}

impl ScillaConfig {
    pub fn load() -> Result<ScillaConfig, ScillaError> {
        let scilla_config_path = scilla_config_path();
        println!("{:?}", scilla_config_path);
        if !scilla_config_path.exists() {
            return Err(ScillaError::ConfigPathDoesntExists);
        }
        let data = fs::read_to_string(scilla_config_path)?;
        let config: ScillaConfig = toml::from_str(&data)?;
        Ok(config)
    }
}
