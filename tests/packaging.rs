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
fn the_docker_config_is_valid_with_and_without_a_token() {
    let text = read("packaging/zoneblick.docker.toml");
    // As shipped it sets no token: the daemon makes one on first start.
    let config = Config::parse(&text).unwrap();
    assert!(config.server.token_sha256.is_none());
    assert_eq!(config.server.bind, "0.0.0.0:8053");
    assert_eq!(config.db_path(), PathBuf::from("/data/zoneblick.sqlite"));
    // The commented line, filled in, is accepted too.
    let hash = "a".repeat(64);
    let line = "# token_sha256 = \"...\"";
    assert!(text.contains(line));
    let config = Config::parse(&text.replace(line, &format!("token_sha256 = \"{hash}\""))).unwrap();
    assert_eq!(config.server.token_sha256.as_deref(), Some(hash.as_str()));
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

/// The install script refuses a "newest release" older than its floor.
/// The floor must be a real version and never ahead of this crate: a
/// floor above the newest published release would refuse every install.
#[test]
fn the_install_script_floor_is_a_version_not_ahead_of_the_crate() {
    let script = read("install.sh");
    let floor = script
        .lines()
        .find_map(|l| l.strip_prefix("FLOOR=\"v"))
        .and_then(|l| l.strip_suffix('"'))
        .expect("install.sh sets FLOOR");
    let parts = |v: &str| -> Vec<u32> { v.split('.').map(|n| n.parse().unwrap()).collect() };
    let (floor, this) = (parts(floor), parts(env!("CARGO_PKG_VERSION")));
    assert_eq!(floor.len(), 3);
    assert!(
        floor <= this,
        "FLOOR {floor:?} is ahead of the crate {this:?}"
    );
}
