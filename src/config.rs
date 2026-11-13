//! The configuration file, `zoneblick.toml`, used by `zoneblick serve`.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::resolver::{name_in_zone, normalise_zone};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{path} is not valid: {message}")]
    Parse { path: PathBuf, message: String },
    #[error("configuration error: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub schedule: ScheduleConfig,
    #[serde(default, rename = "zone")]
    pub zones: Vec<ZoneConfig>,
    #[serde(default)]
    pub alerts: AlertsConfig,
    #[serde(default)]
    pub retention: RetentionConfig,
}

/// How long stored runs are kept.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionConfig {
    /// Every run younger than this is kept.
    #[serde(default = "default_keep_all")]
    pub keep_all: String,
    /// Older runs are thinned to one per day, and deleted after this long.
    #[serde(default = "default_keep_daily")]
    pub keep_daily: String,
}

pub fn default_keep_all() -> String {
    "30d".to_string()
}

pub fn default_keep_daily() -> String {
    "365d".to_string()
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            keep_all: default_keep_all(),
            keep_daily: default_keep_daily(),
        }
    }
}

impl RetentionConfig {
    /// The two limits, in seconds.
    pub fn limits(&self) -> Result<(u64, u64), ConfigError> {
        let all = parse_duration(&self.keep_all)?.as_secs();
        let daily = parse_duration(&self.keep_daily)?.as_secs();
        if daily < all {
            return Err(ConfigError::Invalid(
                "[retention] keep_daily must not be shorter than keep_all".to_string(),
            ));
        }
        Ok((all, daily))
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Address the API and web UI listen on.
    #[serde(default = "default_bind")]
    pub bind: String,
    /// Directory that holds the database file.
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    /// SHA-256 of the API token, in hex. Make one with `zoneblick token`.
    #[serde(default)]
    pub token_sha256: Option<String>,
}

fn default_bind() -> String {
    "127.0.0.1:8053".to_string()
}

fn default_data_dir() -> PathBuf {
    PathBuf::from(".")
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            data_dir: default_data_dir(),
            token_sha256: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduleConfig {
    /// How often every zone is checked, for example "1h" or "30m".
    #[serde(default = "default_every")]
    pub every: String,
    #[serde(default = "default_qps")]
    pub max_qps_per_server: u32,
    /// Accepted for the deep run level in the design; not used yet.
    #[serde(default)]
    pub deep: Option<String>,
}

fn default_every() -> String {
    "1h".to_string()
}

fn default_qps() -> u32 {
    5
}

impl Default for ScheduleConfig {
    fn default() -> Self {
        Self {
            every: default_every(),
            max_qps_per_server: default_qps(),
            deep: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZoneConfig {
    pub name: String,
    /// Names in the zone to check, such as "www" or "mail".
    #[serde(default)]
    pub seeds: Vec<String>,
    /// Name patterns left out of change reports and alerts.
    #[serde(default)]
    pub ignore: Vec<String>,
    /// Where to look for more names, once a day. `"ct"` reads Certificate
    /// Transparency logs through crt.sh; `"axfr"` asks the zone's own
    /// nameservers for a zone transfer.
    #[serde(default)]
    pub discover: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlertsConfig {
    #[serde(default)]
    pub email: Option<EmailConfig>,
    #[serde(default)]
    pub webhook: Option<WebhookConfig>,
    #[serde(default)]
    pub ntfy: Option<NtfyConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmailConfig {
    pub to: String,
    pub from: String,
    pub smtp_host: String,
    #[serde(default = "default_smtp_port")]
    pub smtp_port: u16,
    /// "starttls" (default), "tls" or "none".
    #[serde(default = "default_smtp_tls")]
    pub tls: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    /// Read the password from this file instead of the config.
    #[serde(default)]
    pub password_file: Option<PathBuf>,
}

fn default_smtp_port() -> u16 {
    587
}

fn default_smtp_tls() -> String {
    "starttls".to_string()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookConfig {
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NtfyConfig {
    /// The topic URL, for example https://ntfy.sh/my-topic.
    pub url: String,
    #[serde(default)]
    pub token: Option<String>,
}

/// Parse a length of time such as "45s", "30m", "1h" or "2d".
pub fn parse_duration(text: &str) -> Result<Duration, ConfigError> {
    let text = text.trim();
    let bad = || {
        ConfigError::Invalid(format!(
            "'{text}' is not a length of time; write a number and a unit, such as 30m, 1h or 2d"
        ))
    };
    let split = text.find(|c: char| !c.is_ascii_digit()).ok_or_else(bad)?;
    let (number, unit) = text.split_at(split);
    let n: u64 = number.parse().map_err(|_| bad())?;
    let secs = match unit.trim() {
        "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        "d" => n * 86_400,
        _ => return Err(bad()),
    };
    if secs == 0 {
        return Err(bad());
    }
    Ok(Duration::from_secs(secs))
}

impl Config {
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse(&text).map_err(|e| match e {
            ConfigError::Parse { message, .. } => ConfigError::Parse {
                path: path.to_path_buf(),
                message,
            },
            other => other,
        })
    }

    /// Parse and validate. Zone and seed names come back normalised.
    pub fn parse(text: &str) -> Result<Config, ConfigError> {
        let mut config: Config = toml::from_str(text).map_err(|e| ConfigError::Parse {
            path: PathBuf::from("the configuration"),
            message: e.to_string(),
        })?;
        config.interval()?;
        config.retention.limits()?;
        let bind = config.bind_addr()?;
        if !bind.ip().is_loopback() && config.server.token_sha256.is_none() {
            return Err(ConfigError::Invalid(format!(
                "[server] bind = \"{bind}\" is reachable from other machines, so [server] token_sha256 must be set; make one with `zoneblick token`"
            )));
        }
        if let Some(hash) = &config.server.token_sha256
            && (hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()))
        {
            return Err(ConfigError::Invalid(
                "[server] token_sha256 must be 64 hex characters; make one with `zoneblick token`"
                    .to_string(),
            ));
        }
        if config.schedule.max_qps_per_server == 0 {
            return Err(ConfigError::Invalid(
                "[schedule] max_qps_per_server must be at least 1".to_string(),
            ));
        }
        let mut seen = Vec::new();
        for zone in &mut config.zones {
            let name = normalise_zone(&zone.name)
                .map_err(|e| ConfigError::Invalid(format!("[[zone]] name: {e}")))?;
            if seen.contains(&name) {
                return Err(ConfigError::Invalid(format!("zone {name} is listed twice")));
            }
            let mut seeds = Vec::new();
            for seed in &zone.seeds {
                let full = name_in_zone(&name, seed)
                    .map_err(|e| ConfigError::Invalid(format!("zone {name}, seeds: {e}")))?;
                if full != name && !seeds.contains(&full) {
                    seeds.push(full);
                }
            }
            zone.seeds = seeds;
            if let Some(other) = zone
                .discover
                .iter()
                .find(|d| !matches!(d.as_str(), "ct" | "axfr"))
            {
                return Err(ConfigError::Invalid(format!(
                    "zone {name}, discover: \"{other}\" is not a discovery source; they are \"ct\" and \"axfr\""
                )));
            }
            seen.push(name.clone());
            zone.name = name;
        }
        if let Some(email) = &config.alerts.email
            && !matches!(email.tls.as_str(), "starttls" | "tls" | "none")
        {
            return Err(ConfigError::Invalid(
                "[alerts.email] tls must be \"starttls\", \"tls\" or \"none\"".to_string(),
            ));
        }
        Ok(config)
    }

    pub fn interval(&self) -> Result<Duration, ConfigError> {
        parse_duration(&self.schedule.every)
    }

    pub fn bind_addr(&self) -> Result<SocketAddr, ConfigError> {
        self.server.bind.parse().map_err(|_| {
            ConfigError::Invalid(format!(
                "[server] bind = \"{}\" is not an address and port, such as 127.0.0.1:8053",
                self.server.bind
            ))
        })
    }

    pub fn db_path(&self) -> PathBuf {
        self.server.data_dir.join(crate::cli::DEFAULT_DB)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_design_example_parses() {
        let config = Config::parse(
            r#"
[server]
bind = "127.0.0.1:8053"
data_dir = "/var/lib/zoneblick"

[schedule]
every = "1h"
max_qps_per_server = 5

[[zone]]
name = "Example.org"
seeds = ["www", "api", "mail", "www"]
discover = ["ct", "axfr"]
ignore = ["_acme-challenge.*"]

[alerts.email]
to = "ops@example.org"
from = "zoneblick@example.org"
smtp_host = "smtp.example.org"
"#,
        )
        .unwrap();
        assert_eq!(config.zones.len(), 1);
        assert_eq!(config.zones[0].name, "example.org.");
        assert_eq!(
            config.zones[0].seeds,
            ["www.example.org.", "api.example.org.", "mail.example.org."]
        );
        assert_eq!(config.interval().unwrap(), Duration::from_secs(3600));
        assert_eq!(
            config.db_path(),
            PathBuf::from("/var/lib/zoneblick/zoneblick.sqlite")
        );
        let email = config.alerts.email.unwrap();
        assert_eq!((email.smtp_port, email.tls.as_str()), (587, "starttls"));
    }

    #[test]
    fn an_empty_file_gets_defaults() {
        let config = Config::parse("").unwrap();
        assert_eq!(config.server.bind, "127.0.0.1:8053");
        assert_eq!(config.schedule.every, "1h");
        assert!(config.zones.is_empty());
    }

    #[test]
    fn durations() {
        let secs = |t: &str| parse_duration(t).unwrap().as_secs();
        assert_eq!(
            (secs("45s"), secs("30m"), secs("1h"), secs("2d")),
            (45, 1800, 3600, 172_800)
        );
        for bad in ["", "h", "10", "0m", "1 week", "-5m"] {
            assert!(parse_duration(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn mistakes_are_explained() {
        let err = |text: &str| Config::parse(text).unwrap_err().to_string();
        assert!(err("[server]\nbind = \"0.0.0.0:8053\"").contains("token_sha256"));
        assert!(err("[server]\nbind = \"localhost\"").contains("not an address and port"));
        assert!(err("[schedule]\nevery = \"soon\"").contains("not a length of time"));
        assert!(
            err("[[zone]]\nname = \"a.example\"\n[[zone]]\nname = \"A.example.\"")
                .contains("listed twice")
        );
        assert!(
            err("[[zone]]\nname = \"a.example\"\nseeds = [\"www.other.org.\"]")
                .contains("not inside the zone")
        );
        assert!(
            err("[server]\nbnid = \"x\"").contains("bnid"),
            "unknown keys are refused"
        );
        assert!(err("[server]\ntoken_sha256 = \"abc\"").contains("64 hex"));
        // A public bind with a token is fine.
        let hash = "a".repeat(64);
        assert!(
            Config::parse(&format!(
                "[server]\nbind = \"0.0.0.0:8053\"\ntoken_sha256 = \"{hash}\""
            ))
            .is_ok()
        );
    }
}
