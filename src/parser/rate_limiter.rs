use std::collections::VecDeque;
use std::time::{Duration, SystemTime};

/// Used to allow a rolling-window type rate limit.
/// For example, the NIST API allows up to 5 requests in a 30 second window without an API key, so
/// RateLimiter would be initialized with `RateLimiter::new(window_size: 5, window_duration: Duration::from_secs(30))`
pub struct RateLimiter {
    /// A LIFO queue containing the SystemTime that each run of limit() was called
    run_times: VecDeque<SystemTime>,
    /// The amount of runs that should be allowed within window_duration
    window_size: usize,
    /// The duration of time each
    window_duration: Duration,
    /// Initially `false`, but becomes `true` once the window is saturated.
    window_saturated: bool,
}

impl RateLimiter {
    pub fn new(window_size: usize, window_duration: Duration) -> Self {
        let window_size = if window_size == 0 {
            eprintln!(
                "RateLimiter::window_size must be >0. Returning an instance with a window_size of 1"
            );
            1
        } else {
            window_size
        };

        Self {
            run_times: VecDeque::new(),
            window_size,
            window_duration,
            window_saturated: false,
        }
    }

    /// If the window is saturated, calls `thread::sleep` for the amount of time that needs to be limited.
    pub fn limit(&mut self) {
        if self.run_times.len() == (self.window_size - 1) {
            self.window_saturated = true;
        }

        if self.window_saturated {
            let oldest_run_time = self
                .run_times
                .pop_front()
                .expect("run_times will always have a >1 length if this block is hit");

            let current_time = SystemTime::now();
            let duration_since_oldest = current_time
                .duration_since(oldest_run_time)
                .expect("Time never flows backwards");

            if duration_since_oldest < self.window_duration {
                let sleep_duration = self.window_duration - duration_since_oldest;
                std::thread::sleep(sleep_duration);
            }
        }

        self.run_times.push_back(SystemTime::now());
    }
}
