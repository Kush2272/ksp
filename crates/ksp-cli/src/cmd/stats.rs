//! `ksp stats` — Live server metrics and telemetry.

pub fn run(demo: bool, json: bool) {
    crate::cmd::dashboard::run_stats(demo, json);
}
