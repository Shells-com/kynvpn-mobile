# kynvpn-mobile

The kynvpn app for Android and iOS: a WireGuard VPN client written in Rust,
with the UI on [Stipple](https://github.com/KarpelesLab/stipple) and
WireGuard from [pktkit](https://github.com/KarpelesLab/pktkit-rs).

## Layout

| Path | What |
|---|---|
| `crates/kynvpn-core` | Platform-neutral model: keys, tunnel configuration (`wg-quick` import), config sources |
| `crates/kynvpn-tunnel` | The WireGuard engine: pktkit's `wg::Handler` between a TUN device and a UDP socket |
| `app` | The Stipple app (`cdylib` for Android, binary for iOS and a desktop preview) and the bridge to each platform's VPN service |
| `platform/android`, `platform/ios` | The platform VPN service code (Android `VpnService`, iOS Packet Tunnel extension); coming in M2 and M3 |
| `docs/PLAN.md` | Architecture and the work plan |

## Building

```sh
cargo test                 # core and engine (the engine test runs a WireGuard server on localhost)
cargo run -p kynvpn        # desktop preview of the UI, with a pretend tunnel
cargo check --target aarch64-linux-android --workspace
cargo check --target aarch64-apple-ios --workspace
```

Packaging uses Stipple's `cargo-stipple` (`android`, `ios`), reading
`[package.metadata.stipple]` in `app/Cargo.toml`. The VPN service can't be
packaged yet; see docs/PLAN.md.

## License

GPL-3.0-or-later, like the kynvpn desktop client. See [LICENSE](LICENSE).
