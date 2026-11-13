//! The packaging files stay consistent with each other and with the code.

use std::path::PathBuf;

use zoneblick::config::Config;

fn read(path: &str) -> String {
    std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)).unwrap()
}

#[test]
fn the_site_serves_the_same_install_script() {
    assert!(
        read("install.sh") == read("docs/install.sh"),
        "docs/install.sh is out of date; copy install.sh over it"
    );
}

#[test]
fn the_starter_config_in_the_install_script_is_valid() {
    let script = read("install.sh");
    let start = script.find("<<'CONFIG'\n").unwrap() + "<<'CONFIG'\n".len();
    let end = script.find("\nCONFIG\n").unwrap();
    let config = Config::parse(&script[start..end]).unwrap();
    assert_eq!(config.server.bind, "127.0.0.1:8053");
    assert!(config.zones.is_empty());

    // With its commented examples switched on, it still parses.
    let enabled: String = script[start..end]
        .lines()
        .map(|l| {
            let t = l.strip_prefix("# ").unwrap_or(l);
            let looks_like_toml =
                t.starts_with('[') || (t.contains(" = ") && !t.contains("zoneblick token"));
            if l.starts_with("# ") && looks_like_toml && !t.starts_with("token_sha256") {
                t.to_string()
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    let config = Config::parse(&enabled).unwrap();
    assert_eq!(config.zones[0].name, "example.org.");
    assert!(config.alerts.webhook.is_some() && config.alerts.ntfy.is_some());
    assert_eq!(config.alerts.email.unwrap().smtp_port, 587);
}

#[test]
fn the_docker_config_is_valid_once_a_token_is_set() {
    let text = read("packaging/zoneblick.docker.toml");
    // As shipped it must be refused: the placeholder is not a hash.
    assert!(Config::parse(&text).is_err());
    let hash = "a".repeat(64);
    let config =
        Config::parse(&text.replace("REPLACE_WITH_THE_OUTPUT_OF_THE_TOKEN_COMMAND", &hash))
            .unwrap();
    assert_eq!(config.server.bind, "0.0.0.0:8053");
    assert_eq!(config.db_path(), PathBuf::from("/data/zoneblick.sqlite"));
}

#[test]
fn the_systemd_unit_matches_the_install_script() {
    let unit = read("packaging/zoneblick.service");
    let script = read("install.sh");
    for line in unit
        .lines()
        .filter(|l| l.contains('=') && !l.starts_with('#'))
    {
        let line = line.replace("/usr/local/bin/zoneblick", "$PREFIX/bin/zoneblick");
        assert!(script.contains(&line), "install.sh lacks: {line}");
    }
}
