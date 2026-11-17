//! How the UI asks the platform's VPN service to connect, and hears back.

use kynvpn_core::TunnelConfig;
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VpnStatus {
    Disconnected,
    /// Waiting for the user to allow the VPN (Android's consent dialog, iOS's
    /// "Add VPN Configurations" prompt).
    AwaitingConsent,
    Connecting,
    Connected,
    Failed(String),
}

/// The UI's side of the VPN service.
pub trait VpnControl: Send + Sync {
    /// Start the tunnel. Status changes arrive through `on_status`, from any thread.
    fn connect(&self, cfg: TunnelConfig, on_status: Box<dyn Fn(VpnStatus) + Send + Sync>);
    fn disconnect(&self);
}

/// The controller for the platform being built.
pub fn platform_control() -> Arc<dyn VpnControl> {
    // Android: JNI to KynVpnService (platform/android). iOS:
    // NETunnelProviderManager. Both are milestone M2 in docs/PLAN.md; until
    // then every platform gets the preview controller.
    Arc::new(Preview)
}

/// Pretends to connect, so the UI can be worked on without a device.
struct Preview;

impl VpnControl for Preview {
    fn connect(&self, _cfg: TunnelConfig, on_status: Box<dyn Fn(VpnStatus) + Send + Sync>) {
        std::thread::spawn(move || {
            on_status(VpnStatus::Connecting);
            std::thread::sleep(std::time::Duration::from_millis(800));
            on_status(VpnStatus::Connected);
        });
    }

    fn disconnect(&self) {}
}
