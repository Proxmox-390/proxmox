//! Timestamps in the `%d/%m/%Y:%H:%M:%S %z` format of the access logs.

/// Parses a timestamp like `22/10/2026:14:03:51 +0200` into seconds since the epoch and the UTC
/// offset in seconds.
pub(crate) fn parse_timestamp(time: &str) -> Option<(i64, i32)> {
    let b = time.as_bytes();
    if b.len() != 25
        || b[2] != b'/'
        || b[5] != b'/'
        || b[10] != b':'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b' '
    {
        return None;
    }

    let day = digits(&b[0..2])?;
    let month = digits(&b[3..5])?;
    let year = digits(&b[6..10])?;
    let hour = digits(&b[11..13])?;
    let minute = digits(&b[14..16])?;
    let second = digits(&b[17..19])?;
    let sign = match b[20] {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let offset_hours = digits(&b[21..23])?;
    let offset_minutes = digits(&b[23..25])?;

    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
        || offset_hours > 23
        || offset_minutes > 59
    {
        return None;
    }

    let local_time =
        days_from_civil(year, month, day) * 86400 + i64::from(hour * 3600 + minute * 60 + second);
    let utc_offset = sign * (offset_hours * 3600 + offset_minutes * 60) as i32;

    Some((local_time - i64::from(utc_offset), utc_offset))
}

fn digits(bytes: &[u8]) -> Option<u32> {
    bytes.iter().try_fold(0, |value, &b| {
        b.is_ascii_digit().then(|| value * 10 + u32::from(b - b'0'))
    })
}

fn is_leap_year(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        2 if is_leap_year(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since the epoch of a date in the proleptic Gregorian calendar, using the
/// `days_from_civil` algorithm from Howard Hinnant.
fn days_from_civil(year: u32, month: u32, day: u32) -> i64 {
    // count years from March on, which puts the leap day at the end of a year
    let year = i64::from(year) - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let month_from_march = i64::from((month + 9) % 12);
    let day_of_year = (153 * month_from_march + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;

    era * 146097 + day_of_era - 719468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps() {
        assert_eq!(parse_timestamp("01/01/1970:00:00:00 +0000"), Some((0, 0)));
        assert_eq!(
            parse_timestamp("22/10/2026:14:03:51 +0200"),
            Some((1792670631, 7200))
        );
        assert_eq!(
            parse_timestamp("29/02/2024:23:59:59 -0330"),
            Some((1709263799, -12600))
        );
        assert_eq!(parse_timestamp("31/12/1969:23:59:59 +0000"), Some((-1, 0)));
    }

    #[test]
    fn invalid_timestamps() {
        for time in [
            "",
            "-",
            "22/10/2026:14:03:51",
            "22/10/2026 14:03:51 +0200",
            "22-10-2026:14:03:51 +0200",
            "2/10/2026:14:03:51 +02000",
            "22/Oct/2026:14:03:51 +0200",
            "22/10/2026:14:03:51 0200 ",
            "22/10/2026:14:03:51 +02:0",
            "+2/10/2026:14:03:51 +0200",
            "00/10/2026:14:03:51 +0200",
            "32/10/2026:14:03:51 +0200",
            "31/09/2026:14:03:51 +0200",
            "29/02/2026:14:03:51 +0200",
            "29/02/1900:14:03:51 +0200",
            "22/00/2026:14:03:51 +0200",
            "22/13/2026:14:03:51 +0200",
            "22/10/2026:24:00:00 +0200",
            "22/10/2026:14:60:00 +0200",
            "22/10/2026:14:03:60 +0200",
            "22/10/2026:14:03:51 +2400",
            "22/10/2026:14:03:51 +0260",
            "22/10/2026:14:03:51 \u{2212}02",
        ] {
            assert_eq!(parse_timestamp(time), None, "{time:?}");
        }
        assert!(parse_timestamp("29/02/2000:00:00:00 +0000").is_some());
    }

    #[test]
    fn days_from_civil_is_continuous() {
        let mut expected = days_from_civil(1600, 1, 1);
        for year in 1600..2500 {
            for month in 1..=12 {
                for day in 1..=days_in_month(year, month) {
                    assert_eq!(days_from_civil(year, month, day), expected);
                    expected += 1;
                }
            }
        }
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11017);
    }
}
