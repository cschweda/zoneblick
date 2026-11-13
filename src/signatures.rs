//! Takeover signatures: what a hosting service shows for a site nobody has
//! claimed there. A hostname that is an alias of such a service, and gets
//! that answer, can be claimed by anyone with an account.
//!
//! The texts are imported from the takeover templates of the
//! nuclei-templates project (MIT, see `THIRD-PARTY.md`). Only templates
//! that match on the response body and status are used. The alias
//! suffixes are the services' own hosting domains.

/// One service and how its "nothing here" answer is recognised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature {
    pub service: &'static str,
    /// An alias target under one of these domains is served by the service.
    pub cname_suffixes: &'static [&'static str],
    /// The body must contain every one of these.
    pub all_of: &'static [&'static str],
    /// And, unless empty, at least one of these.
    pub any_of: &'static [&'static str],
    /// And none of these.
    pub none_of: &'static [&'static str],
    /// And the HTTP status must be this, when set.
    pub status: Option<u16>,
}

const fn sig(
    service: &'static str,
    cname_suffixes: &'static [&'static str],
    all_of: &'static [&'static str],
) -> Signature {
    Signature {
        service,
        cname_suffixes,
        all_of,
        any_of: &[],
        none_of: &[],
        status: None,
    }
}

pub const SIGNATURES: &[Signature] = &[
    Signature {
        any_of: &[
            "There isn't a GitHub Pages site here.",
            "For root URLs (like http://example.com/) you must provide an index.html file",
            "The site configured at this address does not contain the requested file.",
            "For root URLs (like <code>http://example.com/</code>)",
        ],
        ..sig("GitHub Pages", &["github.io."], &[])
    },
    sig(
        "Amazon S3",
        &["amazonaws.com."],
        &["The specified bucket does not exist", "BucketName"],
    ),
    Signature {
        status: Some(404),
        ..sig("Surge", &["surge.sh."], &["project not found"])
    },
    sig(
        "Read the Docs",
        &["readthedocs.io."],
        &["unknown to Read the Docs"],
    ),
    sig(
        "Pantheon",
        &["pantheonsite.io."],
        &["The gods are wise, but do not know of the site which you seek."],
    ),
    Signature {
        none_of: &["<title>Please renew your subscription</title>"],
        ..sig(
            "Tilda",
            &["tilda.ws."],
            &["Please go to the site settings and put the domain name in the Domain tab."],
        )
    },
    sig(
        "Strikingly",
        &["strikinglydns.com."],
        &[
            "But if you're looking to build your own website",
            "you've come to the right place.",
        ],
    ),
    Signature {
        none_of: &["cannot be registered"],
        ..sig(
            "WordPress.com",
            &["wordpress.com."],
            &[
                "Do you want to register",
                ".wordpress.com</em> doesn&#8217;t&nbsp;exist",
            ],
        )
    },
    sig(
        "Help Scout",
        &["helpscoutdocs.com."],
        &["No settings were found for this company:"],
    ),
    sig(
        "UserVoice",
        &["uservoice.com."],
        &["This UserVoice subdomain is currently available!"],
    ),
    sig(
        "Cargo",
        &["cargocollective.com."],
        &[
            "If you're moving your domain away from Cargo you must make this configuration through your registrar's DNS control panel.",
        ],
    ),
];

impl Signature {
    /// The signature for the service an alias target belongs to, if any.
    /// `target` is a normalised name with its trailing dot.
    pub fn for_target(target: &str) -> Option<&'static Signature> {
        SIGNATURES.iter().find(|s| {
            s.cname_suffixes.iter().any(|suffix| {
                target == *suffix
                    || target
                        .strip_suffix(suffix)
                        .is_some_and(|rest| rest.ends_with('.'))
            })
        })
    }

    /// True when the answer is the service's "nobody has claimed this".
    pub fn matches(&self, status: u16, body: &str) -> bool {
        self.status.is_none_or(|s| s == status)
            && self.all_of.iter().all(|w| body.contains(w))
            && (self.any_of.is_empty() || self.any_of.iter().any(|w| body.contains(w)))
            && !self.none_of.iter().any(|w| body.contains(w))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_target_is_matched_by_whole_labels() {
        let s = Signature::for_target("someone.github.io.").unwrap();
        assert_eq!(s.service, "GitHub Pages");
        assert!(Signature::for_target("notgithub.io.").is_none());
        assert!(Signature::for_target("github.io.example.org.").is_none());
        assert_eq!(
            Signature::for_target("bucket.s3.eu-west-1.amazonaws.com.")
                .unwrap()
                .service,
            "Amazon S3"
        );
    }

    #[test]
    fn answers_are_matched_on_text_and_status() {
        let pages = Signature::for_target("x.github.io.").unwrap();
        assert!(pages.matches(404, "<p>There isn't a GitHub Pages site here.</p>"));
        assert!(!pages.matches(200, "<h1>My site</h1>"));
        let surge = Signature::for_target("x.surge.sh.").unwrap();
        assert!(
            surge.matches(404, "project not found") && !surge.matches(200, "project not found")
        );
        let wp = Signature::for_target("x.wordpress.com.").unwrap();
        let body = "Do you want to register x? x.wordpress.com</em> doesn&#8217;t&nbsp;exist";
        assert!(wp.matches(200, body));
        assert!(!wp.matches(200, &format!("{body} cannot be registered")));
    }

    #[test]
    fn every_signature_can_match_something() {
        for s in SIGNATURES {
            assert!(!s.cname_suffixes.is_empty(), "{}", s.service);
            assert!(s.cname_suffixes.iter().all(|c| c.ends_with('.')));
            assert!(
                !s.all_of.is_empty() || !s.any_of.is_empty(),
                "{}",
                s.service
            );
        }
    }
}
