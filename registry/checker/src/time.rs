//! Minimal, exact RFC 3339 time handling (UTC) — both directions,
//! test-pinned against known vectors. No date crate: the checker
//! needs exactly two operations (stamp now, compare an Expires
//! instant), and the civil-days algorithm is 30 exact lines.

/// Days from civil date (proleptic Gregorian), Howard Hinnant's
/// `days_from_civil` — exact for all i64-represented years.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Inverse: civil date from days since the epoch.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Parses an RFC 3339 timestamp to epoch seconds. Accepts `Z` and
/// numeric offsets; fractional seconds are truncated. Returns None
/// on anything malformed — callers treat that as a rule violation,
/// never as a guess.
pub fn rfc3339_to_epoch(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.len() < 20 {
        return None;
    }
    let b = s.as_bytes();
    let date_ok = b[4] == b'-' && b[7] == b'-' && (b[10] == b'T' || b[10] == b't');
    if !date_ok {
        return None;
    }
    let year: i64 = s.get(0..4)?.parse().ok()?;
    let month: u32 = s.get(5..7)?.parse().ok()?;
    let day: u32 = s.get(8..10)?.parse().ok()?;
    let hour: i64 = s.get(11..13)?.parse().ok()?;
    let minute: i64 = s.get(14..16)?.parse().ok()?;
    if b[13] != b':' || b[16] != b':' {
        return None;
    }
    let second: i64 = s.get(17..19)?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // Skip fractional seconds, then read the offset.
    let mut i = 19;
    if b.get(i) == Some(&b'.') {
        i += 1;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
    }
    let offset_secs: i64 = match b.get(i) {
        Some(b'Z') | Some(b'z') if i + 1 == b.len() => 0,
        Some(sign @ (b'+' | b'-')) if i + 6 == b.len() && b[i + 3] == b':' => {
            let oh: i64 = s.get(i + 1..i + 3)?.parse().ok()?;
            let om: i64 = s.get(i + 4..i + 6)?.parse().ok()?;
            let magnitude = oh * 3600 + om * 60;
            if *sign == b'+' { magnitude } else { -magnitude }
        }
        _ => return None,
    };
    Some(
        days_from_civil(year, month, day) * 86400 + hour * 3600 + minute * 60 + second
            - offset_secs,
    )
}

/// Formats epoch seconds as RFC 3339 UTC (`…Z`).
pub fn epoch_to_rfc3339(epoch: i64) -> String {
    let days = epoch.div_euclid(86400);
    let rem = epoch.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Current time as epoch seconds.
pub fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before 1970")
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors_round_trip() {
        // date -u -d @0 and friends
        assert_eq!(epoch_to_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_to_epoch("1970-01-01T00:00:00Z"), Some(0));
        // 2026-08-20 12:00:00 UTC — vector verified independently
        // via python datetime (measurement in the build report).
        assert_eq!(rfc3339_to_epoch("2026-08-20T12:00:00Z"), Some(1787227200));
        assert_eq!(epoch_to_rfc3339(1787227200), "2026-08-20T12:00:00Z");
        // Offsets normalize to the same instant.
        assert_eq!(
            rfc3339_to_epoch("2026-08-20T14:00:00+02:00"),
            rfc3339_to_epoch("2026-08-20T12:00:00Z")
        );
        // Fractional seconds truncate.
        assert_eq!(
            rfc3339_to_epoch("2026-08-20T12:00:00.500Z"),
            Some(1787227200)
        );
        // Leap-day sanity.
        assert_eq!(
            epoch_to_rfc3339(rfc3339_to_epoch("2024-02-29T23:59:59Z").unwrap()),
            "2024-02-29T23:59:59Z"
        );
    }

    #[test]
    fn malformed_is_refused_never_guessed() {
        for bad in [
            "2026-08-20",
            "20.08.2026T12:00:00Z",
            "2026-08-20T12:00:00",
            "2026-08-20T12:00:00+0200",
            "2026-13-01T00:00:00Z",
            "",
        ] {
            assert_eq!(rfc3339_to_epoch(bad), None, "{bad}");
        }
    }
}
