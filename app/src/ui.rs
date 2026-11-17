//! The screens. One for now: the connection screen.

use crate::vpn::{VpnControl, VpnStatus};
use kynvpn_core::TunnelConfig;
use std::sync::Arc;
use stipple::prelude::*;

pub struct State {
    vpn: Arc<dyn VpnControl>,
    status: VpnStatus,
    /// The imported configuration. The kynvpn backend will replace this with
    /// a server list once its API is settled.
    config: Option<TunnelConfig>,
}

impl State {
    pub fn new(vpn: Arc<dyn VpnControl>) -> Self {
        Self {
            vpn,
            status: VpnStatus::Disconnected,
            config: demo_config(),
        }
    }
}

pub fn view(state: &State, cx: &mut Cx<State>) -> Element {
    let theme = *cx.theme();
    let on = matches!(
        state.status,
        VpnStatus::Connecting | VpnStatus::Connected | VpnStatus::AwaitingConsent
    );
    let status = match &state.status {
        VpnStatus::Disconnected => "Not connected".to_string(),
        VpnStatus::AwaitingConsent => "Waiting for permission…".to_string(),
        VpnStatus::Connecting => "Connecting…".to_string(),
        VpnStatus::Connected => "Connected".to_string(),
        VpnStatus::Failed(e) => format!("Failed: {e}"),
    };
    let server = match &state.config {
        Some(c) => format!("Server: {}", c.peer.endpoint),
        None => "No server configured".to_string(),
    };
    let handle = cx.handle();
    column(vec![
        heading(cx, "kynvpn"),
        label(cx, server),
        switch(cx, "VPN", on, move |s: &mut State| {
            if on {
                s.vpn.disconnect();
                s.status = VpnStatus::Disconnected;
            } else if let Some(cfg) = s.config.clone() {
                let h = handle.clone();
                s.status = VpnStatus::Connecting;
                s.vpn.connect(
                    cfg,
                    Box::new(move |st| h.update(move |s: &mut State| s.status = st)),
                );
            }
        }),
        label(cx, status),
    ])
    .gap(theme.spacing.md)
    .padding(Insets::uniform(theme.spacing.lg))
}

/// A config to preview the UI with, until import and the backend exist.
fn demo_config() -> Option<TunnelConfig> {
    TunnelConfig::from_wg_quick(
        "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.64.0.2/32\n\
         [Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\n\
         Endpoint = demo.invalid:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n",
    )
    .ok()
}
