// SPDX-License-Identifier: AGPL-3.0-or-later
use serde::{Deserialize, Serialize};
use std::{
    fs, io,
    net::SocketAddr,
    path::{Path, PathBuf},
};
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub api_listen: SocketAddr,
    pub grpc_listen: SocketAddr,
    pub public_api_url: String,
    pub public_agent_url: String,
    pub database_path: PathBuf,
    pub tenant: Tenant,
    pub credentials: Vec<Credential>,
    #[serde(default)]
    pub cors_origins: Vec<String>,
    #[serde(default = "default_limit")]
    pub max_request_bytes: usize,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tenant {
    pub id: Uuid,
    pub name: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub subject: String,
    pub token_sha256: String,
    pub permissions: Vec<String>,
}

const fn default_limit() -> usize {
    8 * 1024 * 1024
}

impl Config {
    pub fn template(database_path: PathBuf, token_hash: String) -> Self {
        Self {
            api_listen: "127.0.0.1:9850".parse().unwrap(),
            grpc_listen: "127.0.0.1:9851".parse().unwrap(),
            public_api_url: "http://127.0.0.1:9850".into(),
            public_agent_url: "http://127.0.0.1:9851".into(),
            database_path,
            tenant: Tenant {
                id: Uuid::new_v4(),
                name: "Default tenant".into(),
            },
            credentials: vec![Credential {
                subject: "admin".into(),
                token_sha256: token_hash,
                permissions: vec!["print".into(), "manage-printers".into()],
            }],
            cors_origins: Vec::new(),
            max_request_bytes: default_limit(),
        }
    }
}

pub fn load(path: &Path) -> anyhow::Result<Config> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(path)?.permissions().mode() & 0o077 != 0 {
            anyhow::bail!("config must not be readable by group or other users");
        }
    }
    let config: Config = toml::from_str(&fs::read_to_string(path)?)?;
    validate(&config)?;
    Ok(config)
}

fn validate(config: &Config) -> anyhow::Result<()> {
    for (name, value) in [
        ("public_api_url", &config.public_api_url),
        ("public_agent_url", &config.public_agent_url),
    ] {
        let url = url::Url::parse(value)?;
        let loopback = url
            .host_str()
            .is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "::1"));
        if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
            anyhow::bail!("{name} must use HTTPS (HTTP is allowed only on loopback)");
        }
    }
    if config.max_request_bytes == 0 || config.max_request_bytes > 32 * 1024 * 1024 {
        anyhow::bail!("max_request_bytes must be between 1 and 33554432");
    }
    if config.credentials.is_empty() {
        anyhow::bail!("at least one API credential is required");
    }
    for origin in &config.cors_origins {
        let url = url::Url::parse(origin)?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
        {
            anyhow::bail!("cors_origins entries must be exact HTTP(S) origins");
        }
    }
    for credential in &config.credentials {
        if credential.subject.trim().is_empty()
            || credential.token_sha256.len() != 64
            || !credential
                .token_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || credential.permissions.is_empty()
            || credential
                .permissions
                .iter()
                .any(|permission| !matches!(permission.as_str(), "print" | "manage-printers"))
        {
            anyhow::bail!("API credential is invalid");
        }
    }
    Ok(())
}

pub fn save(path: &Path, config: &Config) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("tmp");
    fs::write(
        &temporary,
        toml::to_string_pretty(config).map_err(io::Error::other)?,
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
    }
    fs::rename(temporary, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_insecure_non_loopback_urls_and_unknown_permissions() {
        let mut config = Config::template("cloud.sqlite3".into(), "a".repeat(64));
        config.public_agent_url = "http://printer.example".into();
        assert!(validate(&config).is_err());
        config.public_agent_url = "https://printer.example".into();
        config.credentials[0].permissions.push("admin".into());
        assert!(validate(&config).is_err());
    }
}
