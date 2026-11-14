//! Reads a zone file in the standard master-file format (RFC 1035, the
//! format BIND uses and most DNS hosts export) into the record sets it
//! declares, so a run can compare what is served with what was meant.
//!
//! Only the types a run collects are kept: A, AAAA, CNAME, MX, TXT, CAA,
//! and NS. Everything else in the file is read past.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::observe::is_ancestor_or_equal;
use crate::resolver::normalise_zone;

/// The types a declared zone is compared on.
pub const COMPARED: [&str; 7] = ["A", "AAAA", "CNAME", "MX", "TXT", "CAA", "NS"];

/// One record set a zone file declares. The data is in comparison form
/// (see [`comparable`]), sorted and unique.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeclaredSet {
    pub name: String,
    pub rtype: String,
    pub rdata: Vec<String>,
}

/// The record sets a zone is declared to hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Declared {
    /// Where the declaration came from, for messages: the file's path.
    pub source: String,
    pub sets: Vec<DeclaredSet>,
}

impl Declared {
    /// The plain hostnames the file declares, besides the apex: the names
    /// a run should check. Wildcards are left out.
    pub fn names(&self, zone: &str) -> Vec<String> {
        let mut names: Vec<String> = self
            .sets
            .iter()
            .filter(|s| s.name != zone && !s.name.contains('*') && s.rtype != "NS")
            .map(|s| s.name.clone())
            .collect();
        names.sort();
        names.dedup();
        names
    }
}

/// One token of a zone file line; `quoted` tells `"IN"` from `IN`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Token {
    text: String,
    quoted: bool,
}

/// One logical line: its tokens, the line it started on, and whether it
/// began with white space (the owner is then the previous one).
struct Line {
    number: usize,
    indented: bool,
    tokens: Vec<Token>,
}

/// Split the file into logical lines. Parentheses join lines, `;` starts a
/// comment, and both are literal inside quotes.
fn lines(text: &str) -> Result<Vec<Line>, String> {
    let mut out: Vec<Line> = Vec::new();
    let mut current: Option<Line> = None;
    let mut depth = 0usize;
    for (index, raw) in text.lines().enumerate() {
        let number = index + 1;
        let mut chars = raw.chars().peekable();
        if depth == 0 {
            current = Some(Line {
                number,
                indented: raw.starts_with([' ', '\t']),
                tokens: Vec::new(),
            });
        }
        let line = current.as_mut().expect("a line is open");
        while let Some(c) = chars.next() {
            match c {
                ' ' | '\t' | '\r' => {}
                ';' => break,
                '(' => depth += 1,
                ')' => {
                    depth = depth
                        .checked_sub(1)
                        .ok_or(format!("line {number}: ')' without '('"))?;
                }
                '"' => {
                    let mut value = String::new();
                    loop {
                        match chars.next() {
                            None => return Err(format!("line {number}: unclosed quote")),
                            Some('"') => break,
                            Some('\\') => value.push(escape(&mut chars)),
                            Some(c) => value.push(c),
                        }
                    }
                    line.tokens.push(Token {
                        text: value,
                        quoted: true,
                    });
                }
                first => {
                    let mut value = String::new();
                    let mut next = Some(first);
                    while let Some(c) = next {
                        if c == '\\' {
                            value.push(escape(&mut chars));
                        } else {
                            value.push(c);
                        }
                        next = chars.next_if(|c| !matches!(c, ' ' | '\t' | '\r' | ';' | '(' | ')'));
                    }
                    line.tokens.push(Token {
                        text: value,
                        quoted: false,
                    });
                }
            }
        }
        if depth == 0
            && let Some(line) = current.take()
            && !line.tokens.is_empty()
        {
            out.push(line);
        }
    }
    if depth > 0 {
        return Err("the file ends inside parentheses".to_string());
    }
    Ok(out)
}

/// The character after a backslash: `\DDD` is a byte value, anything else
/// is itself.
fn escape(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> char {
    let mut digits = String::new();
    while digits.len() < 3 {
        match chars.next_if(char::is_ascii_digit) {
            Some(d) => digits.push(d),
            None => break,
        }
    }
    if digits.len() == 3 {
        return digits
            .parse::<u8>()
            .map(char::from)
            .unwrap_or(char::REPLACEMENT_CHARACTER);
    }
    if !digits.is_empty() {
        // Not a byte escape after all; the first digit is literal. This
        // drops the rest, which no sane file contains.
        return digits.chars().next().expect("not empty");
    }
    chars.next().unwrap_or('\\')
}

/// A name in the file made absolute: `@` is the origin, a name without a
/// trailing dot is relative to it.
fn absolute(name: &str, origin: &str) -> Option<String> {
    if name == "@" {
        return Some(origin.to_string());
    }
    if name.ends_with('.') {
        return wild_normalise(name);
    }
    if origin == "." {
        wild_normalise(&format!("{name}."))
    } else {
        wild_normalise(&format!("{name}.{origin}"))
    }
}

/// [`normalise_zone`], keeping a leading `*` label.
fn wild_normalise(name: &str) -> Option<String> {
    match name.strip_prefix("*.") {
        Some(rest) => normalise_zone(rest).ok().map(|n| {
            if n == "." {
                "*.".to_string()
            } else {
                format!("*.{n}")
            }
        }),
        None => normalise_zone(name).ok(),
    }
}

fn is_ttl(text: &str) -> bool {
    let mut seen_digit = false;
    !text.is_empty()
        && text.chars().all(|c| {
            if c.is_ascii_digit() {
                seen_digit = true;
                true
            } else {
                seen_digit && matches!(c.to_ascii_lowercase(), 's' | 'm' | 'h' | 'd' | 'w')
            }
        })
        && text.starts_with(|c: char| c.is_ascii_digit())
}

/// The form two record values are compared in, so that spelling does not
/// count as a difference: addresses in their shortest form, names
/// lowercase with a trailing dot, TXT as its joined text.
///
/// `fields` are the fields of the record data; names are made absolute
/// against `origin`. `None` when the data cannot be read as `rtype`.
fn canonical(rtype: &str, fields: &[Token], origin: &str) -> Option<String> {
    // Reading the fields undoes escapes such as `\027`, so the result is
    // made safe to print again before it goes anywhere.
    canonical_raw(rtype, fields, origin).map(|value| crate::resolver::iterate::printable(&value))
}

fn canonical_raw(rtype: &str, fields: &[Token], origin: &str) -> Option<String> {
    let field = |i: usize| fields.get(i).map(|t| t.text.as_str());
    match rtype {
        "A" => Some(field(0)?.parse::<Ipv4Addr>().ok()?.to_string()),
        "AAAA" => Some(field(0)?.parse::<Ipv6Addr>().ok()?.to_string()),
        "CNAME" | "NS" => absolute(field(0)?, origin),
        "MX" => {
            let preference: u16 = field(0)?.parse().ok()?;
            Some(format!("{preference} {}", absolute(field(1)?, origin)?))
        }
        "TXT" => {
            if fields.is_empty() {
                return None;
            }
            Some(fields.iter().map(|t| t.text.as_str()).collect())
        }
        "CAA" => {
            let flags: u8 = field(0)?.parse().ok()?;
            Some(format!(
                "{flags} {} {}",
                field(1)?.to_ascii_lowercase(),
                field(2)?
            ))
        }
        _ => None,
    }
}

/// The comparison form of one value as a run recorded it.
pub fn comparable(rtype: &str, rdata: &str) -> String {
    let tokens = lines(rdata)
        .ok()
        .and_then(|mut l| l.pop())
        .map(|l| l.tokens)
        .unwrap_or_default();
    canonical(rtype, &tokens, ".").unwrap_or_else(|| crate::resolver::iterate::printable(rdata))
}

/// Read a zone file for `zone` (a normalised name).
pub fn parse(zone: &str, text: &str) -> Result<Vec<DeclaredSet>, String> {
    let mut origin = zone.to_string();
    let mut owner: Option<String> = None;
    let mut sets: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
    for line in lines(text)? {
        let n = line.number;
        let first = &line.tokens[0];
        if !first.quoted && first.text.starts_with('$') {
            match first.text.to_ascii_uppercase().as_str() {
                "$ORIGIN" => {
                    let value = line
                        .tokens
                        .get(1)
                        .ok_or(format!("line {n}: $ORIGIN needs a name"))?;
                    origin = absolute(&value.text, &origin)
                        .ok_or(format!("line {n}: '{}' is not a name", value.text))?;
                }
                "$TTL" => {}
                other => {
                    return Err(format!(
                        "line {n}: {other} is not supported; give one flat zone file"
                    ));
                }
            }
            continue;
        }
        let mut rest = &line.tokens[..];
        if !line.indented {
            owner = Some(
                absolute(&first.text, &origin)
                    .ok_or(format!("line {n}: '{}' is not a name", first.text))?,
            );
            rest = &rest[1..];
        }
        let name = owner
            .clone()
            .ok_or(format!("line {n}: a record before any owner name"))?;
        // TTL and class may come in either order, and both may be left out.
        while let Some(token) = rest.first() {
            let upper = token.text.to_ascii_uppercase();
            if !token.quoted
                && (is_ttl(&token.text) || matches!(upper.as_str(), "IN" | "CH" | "HS"))
            {
                rest = &rest[1..];
            } else {
                break;
            }
        }
        let Some(rtype) = rest.first().map(|t| t.text.to_ascii_uppercase()) else {
            return Err(format!("line {n}: no record type"));
        };
        if !COMPARED.contains(&rtype.as_str()) {
            continue;
        }
        if !is_ancestor_or_equal(zone, name.trim_start_matches("*.")) {
            return Err(format!("line {n}: {name} is not inside the zone {zone}"));
        }
        let value = canonical(&rtype, &rest[1..], &origin)
            .ok_or(format!("line {n}: cannot read this {rtype} record"))?;
        sets.entry((name, rtype)).or_default().push(value);
    }
    Ok(sets
        .into_iter()
        .map(|((name, rtype), mut rdata)| {
            rdata.sort();
            rdata.dedup();
            DeclaredSet { name, rtype, rdata }
        })
        .collect())
}

/// Read the zone file at `path`.
pub fn load(zone: &str, path: &std::path::Path) -> Result<Declared, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let sets = parse(zone, &text).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(Declared {
        source: path.display().to_string(),
        sets,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = r#"
$ORIGIN example.org.
$TTL 1h
@   3600 IN SOA ns1.example.org. hostmaster.example.org. (
            2024010101 ; serial
            7200 3600 1209600 300 )
    IN NS  ns1
       NS  ns2.example.net.
@   IN MX  10 mail
    300 IN TXT "v=spf1 include:_spf.example.net " "-all" ; the policy
    IN CAA 0 issue "letsencrypt.org"
www 1d IN A 192.0.2.10
    IN A 192.0.2.11
    IN AAAA 2001:DB8:0:0::1
WWW IN A 192.0.2.10
shop IN 300 CNAME shops.example.net.
*.dev CNAME www
_sip._tcp SRV 0 5 5060 sip
semi TXT "a;b" "c\"d" plain
$ORIGIN eu.example.org.
api A 192.0.2.20
"#;

    fn set<'a>(sets: &'a [DeclaredSet], name: &str, rtype: &str) -> &'a [String] {
        &sets
            .iter()
            .find(|s| s.name == name && s.rtype == rtype)
            .unwrap_or_else(|| panic!("{name} {rtype} missing"))
            .rdata
    }

    #[test]
    fn a_zone_file_is_read() {
        let sets = parse("example.org.", FILE).unwrap();
        assert_eq!(
            set(&sets, "example.org.", "NS"),
            ["ns1.example.org.", "ns2.example.net."]
        );
        assert_eq!(set(&sets, "example.org.", "MX"), ["10 mail.example.org."]);
        assert_eq!(
            set(&sets, "example.org.", "TXT"),
            ["v=spf1 include:_spf.example.net -all"]
        );
        assert_eq!(
            set(&sets, "example.org.", "CAA"),
            ["0 issue letsencrypt.org"]
        );
        assert_eq!(
            set(&sets, "www.example.org.", "A"),
            ["192.0.2.10", "192.0.2.11"]
        );
        assert_eq!(set(&sets, "www.example.org.", "AAAA"), ["2001:db8::1"]);
        assert_eq!(
            set(&sets, "shop.example.org.", "CNAME"),
            ["shops.example.net."]
        );
        assert_eq!(
            set(&sets, "*.dev.example.org.", "CNAME"),
            ["www.example.org."]
        );
        assert_eq!(set(&sets, "semi.example.org.", "TXT"), ["a;bc\"dplain"]);
        assert_eq!(set(&sets, "api.eu.example.org.", "A"), ["192.0.2.20"]);
        // SOA and SRV are read past.
        assert!(sets.iter().all(|s| COMPARED.contains(&s.rtype.as_str())));

        let declared = Declared {
            source: "f".to_string(),
            sets,
        };
        assert_eq!(
            declared.names("example.org."),
            [
                "api.eu.example.org.",
                "semi.example.org.",
                "shop.example.org.",
                "www.example.org."
            ]
        );
    }

    #[test]
    fn recorded_values_compare_equal_to_declared_ones() {
        assert_eq!(comparable("TXT", r#""v=spf1 " "-all""#), "v=spf1 -all");
        assert_eq!(comparable("TXT", r#""say \"hi\" \\ x""#), r#"say "hi" \ x"#);
        assert_eq!(
            comparable("CAA", r#"0 issue "letsencrypt.org""#),
            "0 issue letsencrypt.org"
        );
        assert_eq!(
            comparable("MX", "10 mail.example.org."),
            "10 mail.example.org."
        );
        assert_eq!(comparable("AAAA", "2001:db8::1"), "2001:db8::1");
        assert_eq!(comparable("A", "not an address"), "not an address");
    }

    #[test]
    fn mistakes_name_the_line() {
        let err = |text: &str| parse("example.org.", text).unwrap_err();
        assert_eq!(
            err("www A 192.0.2.300"),
            "line 1: cannot read this A record"
        );
        assert!(err("\n$INCLUDE other.zone").starts_with("line 2: $INCLUDE is not supported"));
        assert!(err("www.other.net. A 192.0.2.1").contains("not inside the zone"));
        assert!(err("@ TXT \"open").contains("unclosed quote"));
        assert!(err("@ SOA a b ( 1 2 3").contains("inside parentheses"));
        assert!(err("  A 192.0.2.1").contains("before any owner"));
    }
}
