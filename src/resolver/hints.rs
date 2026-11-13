//! Built-in root hints (the root server addresses, from the IANA named.root file).

use std::net::IpAddr;

/// Root server names with their IPv4 and IPv6 addresses.
pub const ROOT_HINTS: &[(&str, &str, &str)] = &[
    ("a.root-servers.net.", "198.41.0.4", "2001:503:ba3e::2:30"),
    ("b.root-servers.net.", "170.247.170.2", "2801:1b8:10::b"),
    ("c.root-servers.net.", "192.33.4.12", "2001:500:2::c"),
    ("d.root-servers.net.", "199.7.91.13", "2001:500:2d::d"),
    ("e.root-servers.net.", "192.203.230.10", "2001:500:a8::e"),
    ("f.root-servers.net.", "192.5.5.241", "2001:500:2f::f"),
    ("g.root-servers.net.", "192.112.36.4", "2001:500:12::d0d"),
    ("h.root-servers.net.", "198.97.190.53", "2001:500:1::53"),
    ("i.root-servers.net.", "192.36.148.17", "2001:7fe::53"),
    ("j.root-servers.net.", "192.58.128.30", "2001:503:c27::2:30"),
    ("k.root-servers.net.", "193.0.14.129", "2001:7fd::1"),
    ("l.root-servers.net.", "199.7.83.42", "2001:500:9f::42"),
    ("m.root-servers.net.", "202.12.27.33", "2001:dc3::35"),
];

/// The root servers as (name, addresses) pairs.
pub fn root_servers() -> Vec<(String, Vec<IpAddr>)> {
    ROOT_HINTS
        .iter()
        .map(|(name, v4, v6)| {
            let addrs = [v4, v6]
                .iter()
                .map(|a| a.parse().expect("root hint address is valid"))
                .collect();
            (name.to_string(), addrs)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hints_parse() {
        let roots = root_servers();
        assert_eq!(roots.len(), 13);
        for (_, addrs) in roots {
            assert!(addrs[0].is_ipv4());
            assert!(addrs[1].is_ipv6());
        }
    }
}
