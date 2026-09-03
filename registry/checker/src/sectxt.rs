//! security.txt evaluation (RFC 9116) per the launch runbook's BACS
//! rules: `Contact` and `Expires` are required (RB-R-BACS-8/-9), an
//! expired `Expires` gets a grace window before it hard-fails, and
//! unknown fields are TOLERATED (RB-R-BACS-12) — the standard is
//! extensible, a checker that fails on extensions is wrong.

use crate::time::rfc3339_to_epoch;

/// Grace window after `Expires` (seconds): 30 days. Within it the
/// state is a visible warning, not a failure — operators get the
/// chance the runbook rules promise.
pub const EXPIRES_GRACE_SECS: i64 = 30 * 86400;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecTxtStatus {
    Valid,
    /// Expired, but within the grace window.
    ExpiredInGrace {
        expired_at: String,
    },
    Invalid {
        reasons: Vec<String>,
    },
}

/// Parses field lines (RFC 9116: `Name: value`, names
/// case-insensitive, `#` comments); malformed lines are reported by
/// the caller via evaluate(), unknown field NAMES are kept and
/// tolerated.
fn fields(content: &str) -> Vec<(String, String)> {
    content
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .filter_map(|l| {
            let (name, value) = l.split_once(':')?;
            Some((name.trim().to_ascii_lowercase(), value.trim().to_string()))
        })
        .collect()
}

/// Evaluates a security.txt body at instant `now` (epoch seconds).
pub fn evaluate(content: &str, now: i64) -> SecTxtStatus {
    let fields = fields(content);
    let mut reasons = Vec::new();

    if !fields.iter().any(|(n, v)| n == "contact" && !v.is_empty()) {
        reasons.push("required field Contact missing".to_string());
    }

    let mut in_grace: Option<String> = None;
    match fields.iter().find(|(n, _)| n == "expires") {
        None => reasons.push("required field Expires missing".to_string()),
        Some((_, value)) => match rfc3339_to_epoch(value) {
            None => reasons.push(format!("Expires not RFC 3339: «{value}»")),
            Some(expires) if now <= expires => {}
            Some(expires) if now <= expires + EXPIRES_GRACE_SECS => {
                in_grace = Some(value.clone());
            }
            Some(_) => reasons.push(format!("Expires past the grace window: {value}")),
        },
    }

    if !reasons.is_empty() {
        SecTxtStatus::Invalid { reasons }
    } else if let Some(expired_at) = in_grace {
        SecTxtStatus::ExpiredInGrace { expired_at }
    } else {
        SecTxtStatus::Valid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_787_227_200; // 2026-08-20T12:00:00Z, pinned vector

    #[test]
    fn valid_file_with_unknown_fields_tolerated() {
        let content = "# comment\nContact: mailto:security@example.org\n\
                       Expires: 2027-01-01T00:00:00Z\nX-Custom-Field: anything\n";
        assert_eq!(evaluate(content, NOW), SecTxtStatus::Valid);
    }

    #[test]
    fn missing_contact_fires() {
        let content = "Expires: 2027-01-01T00:00:00Z\n";
        let SecTxtStatus::Invalid { reasons } = evaluate(content, NOW) else {
            panic!("expected Invalid");
        };
        assert!(reasons.iter().any(|r| r.contains("Contact")));
    }

    #[test]
    fn missing_expires_fires() {
        let content = "Contact: mailto:security@example.org\n";
        let SecTxtStatus::Invalid { reasons } = evaluate(content, NOW) else {
            panic!("expected Invalid");
        };
        assert!(reasons.iter().any(|r| r.contains("Expires missing")));
    }

    #[test]
    fn expired_within_grace_is_a_warning_state() {
        // Expired 10 days before NOW — inside the 30-day window.
        let content = "Contact: mailto:s@example.org\nExpires: 2026-08-10T12:00:00Z\n";
        assert!(matches!(
            evaluate(content, NOW),
            SecTxtStatus::ExpiredInGrace { .. }
        ));
    }

    #[test]
    fn expired_past_grace_fails() {
        let content = "Contact: mailto:s@example.org\nExpires: 2026-06-01T00:00:00Z\n";
        assert!(matches!(
            evaluate(content, NOW),
            SecTxtStatus::Invalid { .. }
        ));
    }

    #[test]
    fn field_names_are_case_insensitive() {
        let content = "cOnTaCt: mailto:s@example.org\nEXPIRES: 2027-01-01T00:00:00Z\n";
        assert_eq!(evaluate(content, NOW), SecTxtStatus::Valid);
    }

    #[test]
    fn unparsable_expires_is_refused_never_guessed() {
        let content = "Contact: mailto:s@example.org\nExpires: next year\n";
        assert!(matches!(
            evaluate(content, NOW),
            SecTxtStatus::Invalid { .. }
        ));
    }
}
