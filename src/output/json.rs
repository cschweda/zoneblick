//! JSON output: one document on stdout.

use serde::Serialize;

/// Pretty-printed JSON with a trailing newline. Field order follows the
/// struct definitions, so the same run always renders the same bytes.
pub fn render<T: Serialize>(doc: &T) -> String {
    let mut out = serde_json::to_string_pretty(doc).expect("report types always serialise");
    out.push('\n');
    out
}
