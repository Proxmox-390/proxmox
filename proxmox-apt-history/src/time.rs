const DAY: i64 = 24 * 60 * 60;

unsafe extern "C" {
    // not bound by the libc crate
    fn tzset();
}

/// Makes the following conversions use the current time zone of the system.
///
/// Unlike `mktime`, `localtime_r` does not check for time zone changes by itself.
pub(crate) fn update_time_zone() {
    // SAFETY: only (re)initializes the time zone state of libc, which is protected by a lock.
    unsafe { tzset() }
}

/// Parses a timestamp as APT writes it to its logs, i.e. local time formatted as `%F  %T`, into a
/// Unix epoch.
///
/// APT does not log the UTC offset, so the conversion uses the time zone of the process, see
/// [`update_time_zone`] and [`resolve_local_time`] for the handling of ambiguous local times.
pub(crate) fn parse_log_time(value: &str) -> Option<i64> {
    let (date, time) = value.trim().split_once(' ')?;
    let mut date = date.split('-');
    let mut time = time.trim_start().split(':');

    let fields = [
        number(date.next()?, 0, 9999)?,
        number(date.next()?, 1, 12)?,
        number(date.next()?, 1, 31)?,
        number(time.next()?, 0, 23)?,
        number(time.next()?, 0, 59)?,
        number(time.next()?, 0, 59)?,
    ];
    if date.next().is_some() || time.next().is_some() {
        return None;
    }

    resolve_local_time(naive_epoch(fields)?, utc_offset)
}

/// Converts local time into the epoch it would have if it was UTC, rejecting invalid dates like
/// February 30, which `timegm` would normalize.
fn naive_epoch([year, month, day, hour, minute, second]: [i32; 6]) -> Option<i64> {
    // SAFETY: all-zero is a valid `libc::tm`, with a null pointer as `tm_zone`.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    tm.tm_year = year - 1900;
    tm.tm_mon = month - 1;
    tm.tm_mday = day;
    tm.tm_hour = hour;
    tm.tm_min = minute;
    tm.tm_sec = second;

    let epoch = proxmox_time::timegm(&mut tm).ok()?;

    let normalized = [
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
    ];
    (normalized == [year, month, day, hour, minute, second]).then_some(epoch)
}

/// Returns the UTC offset in seconds of the local time zone at `epoch`.
fn utc_offset(epoch: i64) -> Option<i64> {
    Some(proxmox_time::localtime(epoch).ok()?.tm_gmtoff)
}

/// Converts a local time, given as the epoch it would have if it was UTC, into a Unix epoch using
/// `utc_offset` to look up the UTC offset of the local time zone at an epoch.
///
/// For a local time that occurs twice because the clock was set back, for example at the end of
/// daylight saving time, the earlier epoch is used. So the result is deterministic, which `mktime`
/// does not guarantee, but not necessarily the original instant. A local time in the gap after the
/// clock was set forward, which APT can only have logged before a time zone change, is resolved
/// with the offset from before the gap, like `mktime` does.
///
/// This assumes that the offsets in effect a day before and after the local time are the only ones
/// within that range, which holds for all real time zones.
fn resolve_local_time(naive: i64, utc_offset: impl Fn(i64) -> Option<i64>) -> Option<i64> {
    let before = utc_offset(naive - DAY)?;
    let after = utc_offset(naive + DAY)?;

    let matching = [naive - before, naive - after]
        .into_iter()
        .filter(|&epoch| utc_offset(epoch) == Some(naive - epoch))
        .min();
    if matching.is_some() {
        return matching;
    }

    let in_forward_gap = after > before
        && utc_offset(naive - before) == Some(after)
        && utc_offset(naive - after) == Some(before);
    in_forward_gap.then_some(naive - before)
}

/// Parses a plain decimal number, rejecting values outside of `min..=max`.
fn number(value: &str, min: i32, max: i32) -> Option<i32> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value.parse().ok().filter(|n| (min..=max).contains(n))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Converts back to local time, as the expected epoch depends on the time zone of the test.
    fn local_time(epoch: i64) -> (i32, i32, i32, i32, i32, i32) {
        let tm = proxmox_time::localtime(epoch).expect("valid epoch");
        (
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec,
        )
    }

    #[test]
    fn parse_valid() {
        update_time_zone();

        let epoch = parse_log_time("2026-10-01  11:33:47").expect("valid timestamp");
        assert_eq!(local_time(epoch), (2026, 10, 1, 11, 33, 47));

        let end = parse_log_time("2026-10-01  11:34:22").expect("valid timestamp");
        assert_eq!(end - epoch, 35);

        assert_eq!(parse_log_time(" 2026-10-01 11:33:47 "), Some(epoch));
    }

    #[test]
    fn parse_invalid() {
        for value in [
            "",
            "2026-10-01",
            "2026-10-01  11:33",
            "2026-13-01  11:33:47",
            "2026-10-00  11:33:47",
            "2026-02-30  11:33:47",
            "2026-10-01  24:00:00",
            "2026-10-01  11:33:60",
            "2026-10-01  11:33:47:00",
            "2026-10-01-01  11:33:47",
            "2026-10-+1  11:33:47",
            "2026/10/01  11:33:47",
        ] {
            assert_eq!(parse_log_time(value), None, "{value:?}");
        }
    }

    // A zone with UTC offset +1h that switches to +2h at epoch `SWITCH`, so the local times from
    // 02:00 to 03:00 after midnight of `SWITCH` do not exist, and back at `SWITCH_BACK`, so the
    // local times from 02:00 to 03:00 exist twice.
    const SWITCH: i64 = 100 * DAY + 3600;
    const SWITCH_BACK: i64 = 200 * DAY + 3600;

    fn modeled_offset(epoch: i64) -> Option<i64> {
        Some(if (SWITCH..SWITCH_BACK).contains(&epoch) {
            7200
        } else {
            3600
        })
    }

    #[test]
    fn resolve_unambiguous() {
        // 12:00 local on day 50 and day 150, so in standard and daylight saving time
        assert_eq!(
            resolve_local_time(50 * DAY + 12 * 3600, modeled_offset),
            Some(50 * DAY + 11 * 3600)
        );
        assert_eq!(
            resolve_local_time(150 * DAY + 12 * 3600, modeled_offset),
            Some(150 * DAY + 10 * 3600)
        );
    }

    #[test]
    fn resolve_repeated_hour() {
        // 02:30 local exists at 00:30 UTC with +2h and at 01:30 UTC with +1h, take the earlier
        assert_eq!(
            resolve_local_time(200 * DAY + 2 * 3600 + 1800, modeled_offset),
            Some(200 * DAY + 1800)
        );
        // the instants right before and after the repeated hour are unambiguous
        assert_eq!(
            resolve_local_time(200 * DAY + 3600 + 1800, modeled_offset),
            Some(200 * DAY - 1800)
        );
        assert_eq!(
            resolve_local_time(200 * DAY + 3 * 3600 + 1800, modeled_offset),
            Some(200 * DAY + 2 * 3600 + 1800)
        );
    }

    #[test]
    fn resolve_forward_gap() {
        // 02:30 local does not exist, resolved with the +1h offset from before the gap
        assert_eq!(
            resolve_local_time(100 * DAY + 2 * 3600 + 1800, modeled_offset),
            Some(100 * DAY + 3600 + 1800)
        );
    }

    #[test]
    fn resolve_no_match() {
        assert_eq!(resolve_local_time(50 * DAY, |_| None), None);

        // an offset that only applies for a few hours is not seen by the lookups a day before and
        // after, so no candidate matches, which must not be mistaken for a forward gap
        let naive = 50 * DAY;
        let short_lived = |epoch: i64| {
            Some(if (naive - 7200..naive + 7200).contains(&epoch) {
                3600
            } else {
                0
            })
        };
        assert_eq!(resolve_local_time(naive, short_lived), None);
    }
}
