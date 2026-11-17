//! The kynvpn app: the UI, and the bridge to each platform's VPN service.
//!
//! The UI never runs the tunnel itself. On Android the tunnel lives in our
//! `VpnService` (which outlives the activity), on iOS in the Packet Tunnel
//! extension (a separate process). The UI talks to it through
//! [`vpn::VpnControl`].

mod ui;
pub mod vpn;

use stipple::prelude::*;

pub fn main() {
    let state = ui::State::new(vpn::platform_control());
    App::new(state, ui::view)
        .title("kynvpn")
        .theme(Theme::native())
        .run();
}

#[cfg(target_os = "android")]
mod android_entry {
    use std::ffi::c_void;
    use stipple::platform::backend::android::{self, ANativeActivity};

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn ANativeActivity_onCreate(
        activity: *mut ANativeActivity,
        saved_state: *mut c_void,
        saved_state_size: usize,
    ) {
        unsafe { android::start(activity, saved_state, saved_state_size, super::main) };
    }
}
