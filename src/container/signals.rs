use nix::sys::signal::Signal;
use std::os::unix::thread::JoinHandleExt;
use std::thread::JoinHandle;
use tracing::debug;

pub(super) fn wake_sigwait_thread(handle: &JoinHandle<()>, signal: Signal) {
    // SAFETY: the signal-forwarding thread inherits `signal` blocked in its
    // mask before it starts waiting on the same signal set. Targeting that
    // exact pthread wakes sigwait without letting the signal's default action
    // run on an unrelated host thread.
    let result = unsafe { libc::pthread_kill(handle.as_pthread_t(), signal as libc::c_int) };
    if result != 0 {
        debug!(
            error = %std::io::Error::from_raw_os_error(result),
            ?signal,
            "failed to wake signal-forwarding thread"
        );
    }
}
