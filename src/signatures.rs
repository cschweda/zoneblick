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
    /// Compare the texts without regard to letter case.
    pub ignore_case: bool,
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
        ignore_case: false,
    }
}

/// A service recognised by any one of several texts.
const fn any(
    service: &'static str,
    cname_suffixes: &'static [&'static str],
    any_of: &'static [&'static str],
) -> Signature {
    Signature {
        any_of,
        ..sig(service, cname_suffixes, &[])
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
    Signature {
        ignore_case: true,
        ..any(
            "Zendesk",
            &["zendesk.com."],
            &["this help centre no longer exists", "Help Centre Closed"],
        )
    },
    sig(
        "Intercom",
        &["custom.intercom.help."],
        &["This page is reserved for artistic dogs."],
    ),
    sig(
        "LaunchRock",
        &["launchrock.com."],
        &[
            "It looks like you may have taken a wrong turn somewhere. Don't worry...it happens to all of us.",
        ],
    ),
    sig("ReadMe", &["readme.io."], &["Project doesnt exist... yet!"]),
    sig(
        "Agile CRM",
        &["agilecrm.com."],
        &["Sorry, this page is no longer available."],
    ),
    sig(
        "Aha!",
        &["aha.io."],
        &["There is no portal here ... sending you back to Aha!"],
    ),
    sig(
        "Canny",
        &["canny.io."],
        &[
            "Company Not Found",
            "There is no such company. Did you enter the right URL?",
        ],
    ),
    sig(
        "Campaign Monitor",
        &["createsend.com."],
        &["Email Newsletter Software", "css.createsend1.com"],
    ),
    sig(
        "GetResponse",
        &["gr8.com."],
        &["With GetResponse Landing Pages, lead generation has never been easier"],
    ),
    sig(
        "Helpjuice",
        &["helpjuice.com."],
        &["We could not find what you're looking for."],
    ),
    any(
        "Helprace",
        &["helprace.com."],
        &[
            "Alias not configured!",
            "Admin of this Helprace account needs to set up domain alias",
        ],
    ),
    sig("Kinsta", &["kinsta.cloud."], &["No Site For Domain"]),
    any(
        "ngrok",
        &["ngrok.io."],
        &["ngrok.io not found", "Tunnel *.ngrok.io not found"],
    ),
    any(
        "Pingdom",
        &["stats.pingdom.com."],
        &[
            "Public Report Not Activated",
            "This public report page has not been activated by the user",
        ],
    ),
    sig(
        "SmugMug",
        &["domains.smugmug.com."],
        &["{\"text\":\"Page Not Found\""],
    ),
    sig(
        "SurveySparrow",
        &["surveysparrow.com."],
        &["Account not found.", "ouch!", "SurveySparrow"],
    ),
    sig(
        "Teamwork",
        &["teamwork.com."],
        &["Oops - We didn't find your site."],
    ),
    sig(
        "Uberflip",
        &["read.uberflip.com."],
        &["Non-hub domain, The URL you've accessed does not provide a hub."],
    ),
    sig(
        "Vend",
        &["vendecommerce.com."],
        &["Looks like you've traveled too far into cyberspace."],
    ),
    any(
        "Wishpond",
        &["wishpond.com."],
        &[
            "https://www.wishpond.com/404?campaign=true",
            "Oops! There isn’t a Wishpond Campaign published to this page.",
        ],
    ),
    sig(
        "Wufoo",
        &["wufoo.com."],
        &["Profile not found", "Hmmm....something is not right."],
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
        let folded;
        let body = if self.ignore_case {
            folded = body.to_lowercase();
            folded.as_str()
        } else {
            body
        };
        let has = |w: &&str| {
            if self.ignore_case {
                body.contains(&w.to_lowercase())
            } else {
                body.contains(*w)
            }
        };
        self.status.is_none_or(|s| s == status)
            && self.all_of.iter().all(has)
            && (self.any_of.is_empty() || self.any_of.iter().any(has))
            && !self.none_of.iter().any(has)
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
    fn case_is_ignored_only_where_the_signature_says_so() {
        let zendesk = Signature::for_target("acme.zendesk.com.").unwrap();
        assert!(zendesk.matches(200, "<h1>Help centre closed</h1>"));
        let kinsta = Signature::for_target("acme.kinsta.cloud.").unwrap();
        assert!(kinsta.matches(404, "No Site For Domain"));
        assert!(!kinsta.matches(404, "no site for domain"));
        let names: std::collections::BTreeSet<&str> =
            SIGNATURES.iter().map(|s| s.service).collect();
        assert_eq!(names.len(), SIGNATURES.len(), "a service is listed twice");
        assert_eq!(SIGNATURES.len(), 32);
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
