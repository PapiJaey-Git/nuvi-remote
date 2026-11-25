use chrono::{DateTime, Datelike, Duration, Local, NaiveTime, TimeZone, Utc, Weekday};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RotationSchedule {
    EveryNDays {
        days: u16,
    },
    Weekdays {
        mon: bool,
        tue: bool,
        wed: bool,
        thu: bool,
        fri: bool,
        sat: bool,
        sun: bool,
    },
}

impl Default for RotationSchedule {
    fn default() -> Self {
        Self::EveryNDays { days: 7 }
    }
}

impl RotationSchedule {
    pub fn weekday_enabled(&self, wd: Weekday) -> bool {
        match self {
            RotationSchedule::EveryNDays { .. } => false,
            RotationSchedule::Weekdays {
                mon,
                tue,
                wed,
                thu,
                fri,
                sat,
                sun,
            } => match wd {
                Weekday::Mon => *mon,
                Weekday::Tue => *tue,
                Weekday::Wed => *wed,
                Weekday::Thu => *thu,
                Weekday::Fri => *fri,
                Weekday::Sat => *sat,
                Weekday::Sun => *sun,
            },
        }
    }

    pub fn has_any_weekday(&self) -> bool {
        match self {
            RotationSchedule::EveryNDays { .. } => true,
            RotationSchedule::Weekdays {
                mon,
                tue,
                wed,
                thu,
                fri,
                sat,
                sun,
            } => *mon || *tue || *wed || *thu || *fri || *sat || *sun,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnattendedKeyState {
    pub enabled: bool,
    pub schedule: RotationSchedule,
    pub rotate_after_session: bool,
    pub key_hash: Option<String>,
    pub created_at: DateTime<Utc>,
    pub next_rotation_at: DateTime<Utc>,
    pub failed_attempts: u32,
    pub locked_until: Option<DateTime<Utc>>,
}

impl Default for UnattendedKeyState {
    fn default() -> Self {
        let now = Utc::now();
        let schedule = RotationSchedule::default();
        let next = compute_next_rotation_utc(&schedule, now);
        Self {
            enabled: false,
            schedule,
            rotate_after_session: false,
            key_hash: None,
            created_at: now,
            next_rotation_at: next,
            failed_attempts: 0,
            locked_until: None,
        }
    }
}

/// Computes the next rotation timestamp in UTC given a schedule and a local reference time.
pub fn compute_next_rotation<Tz: TimeZone>(
    schedule: &RotationSchedule,
    from_local: DateTime<Tz>,
) -> DateTime<Utc> {
    match schedule {
        RotationSchedule::EveryNDays { days } => {
            let clamped = (*days).clamp(1, 365) as i64;
            (from_local + Duration::days(clamped)).with_timezone(&Utc)
        }
        RotationSchedule::Weekdays { .. } => {
            if !schedule.has_any_weekday() {
                return (from_local + Duration::days(7)).with_timezone(&Utc);
            }
            let base_date = from_local.date_naive();
            for offset in 1..=7 {
                let candidate_date = base_date + Duration::days(offset);
                if schedule.weekday_enabled(candidate_date.weekday()) {
                    let naive_dt =
                        candidate_date.and_time(NaiveTime::from_hms_opt(0, 0, 0).unwrap());
                    if let Some(dt) = from_local.timezone().from_local_datetime(&naive_dt).earliest()
                    {
                        return dt.with_timezone(&Utc);
                    }
                }
            }
            (from_local + Duration::days(7)).with_timezone(&Utc)
        }
    }
}

pub fn compute_next_rotation_utc(schedule: &RotationSchedule, now: DateTime<Utc>) -> DateTime<Utc> {
    let local_ref = now.with_timezone(&Local);
    compute_next_rotation(schedule, local_ref)
}

pub fn is_rotation_due(state: &UnattendedKeyState, now: DateTime<Utc>) -> bool {
    state.enabled && (state.key_hash.is_none() || now >= state.next_rotation_at)
}

pub fn is_locked_out(state: &UnattendedKeyState, now: DateTime<Utc>) -> Option<i64> {
    state.locked_until.and_then(|until| {
        let secs = (until - now).num_seconds();
        if secs > 0 {
            Some(secs)
        } else {
            None
        }
    })
}

pub fn record_failed_attempt(state: &mut UnattendedKeyState, now: DateTime<Utc>) {
    state.failed_attempts = state.failed_attempts.saturating_add(1);
    if state.failed_attempts >= 5 {
        let tier = (state.failed_attempts - 5).min(4);
        let mins = (5i64 * (1i64 << tier)).min(60);
        state.locked_until = Some(now + Duration::minutes(mins));
    }
}

pub fn reset_failures(state: &mut UnattendedKeyState) {
    state.failed_attempts = 0;
    state.locked_until = None;
}

pub fn human_countdown(next_rotation_at: DateTime<Utc>, now: DateTime<Utc>) -> String {
    let diff = next_rotation_at - now;
    if diff.num_seconds() <= 0 {
        return "Rotation due now".to_string();
    }
    let days = diff.num_days();
    let hours = diff.num_hours() % 24;
    let mins = diff.num_minutes() % 60;
    if days > 0 {
        format!("Rotates in {days}d {hours}h")
    } else if hours > 0 {
        format!("Rotates in {hours}h {mins}m")
    } else {
        format!("Rotates in {}m", mins.max(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn every_n_days_adds_exact_days() {
        let start = Utc.with_ymd_and_hms(2026, 11, 24, 10, 0, 0).unwrap();
        let next = compute_next_rotation(&RotationSchedule::EveryNDays { days: 3 }, start);
        assert_eq!(next, Utc.with_ymd_and_hms(2026, 11, 27, 10, 0, 0).unwrap());
    }

    #[test]
    fn weekdays_picks_next_midnight() {
        // 2026-11-24 is Tuesday
        let tuesday = Utc.with_ymd_and_hms(2026, 11, 24, 15, 30, 0).unwrap();
        let sched = RotationSchedule::Weekdays {
            mon: true,
            tue: false,
            wed: false,
            thu: true,
            fri: false,
            sat: false,
            sun: false,
        };
        let next = compute_next_rotation(&sched, tuesday);
        // Next matching day is Thursday 2026-11-26 00:00:00 UTC
        assert_eq!(next, Utc.with_ymd_and_hms(2026, 11, 26, 0, 0, 0).unwrap());
    }

    #[test]
    fn lockout_after_five_failures() {
        let mut state = UnattendedKeyState::default();
        let now = Utc.with_ymd_and_hms(2026, 11, 24, 12, 0, 0).unwrap();
        for _ in 0..4 {
            record_failed_attempt(&mut state, now);
            assert!(is_locked_out(&state, now).is_none());
        }
        record_failed_attempt(&mut state, now);
        let secs = is_locked_out(&state, now).expect("should lock on 5th failure");
        assert_eq!(secs, 300);

        reset_failures(&mut state);
        assert!(is_locked_out(&state, now).is_none());
    }
}
