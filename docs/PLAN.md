# kynvpn-mobile: architecture and plan

## Architecture

```
┌──────────────── app (Stipple UI) ────────────────┐
│ screens · settings · VpnControl                  │
└───────┬──────────────────────────────────┬───────┘
        │ Android: JNI                     │ iOS: NETunnelProviderManager
┌───────▼─────────────────┐    ┌───────────▼───────────────────┐
│ KynVpnService (Java,    │    │ Packet Tunnel extension       │
│ platform/android)       │    │ (.appex, platform/ios)        │
│ VpnService.Builder,     │    │ NEPacketTunnelProvider,       │
│ protect(), foreground   │    │ NWPathMonitor                 │
│ notification            │    │                               │
└───────┬─────────────────┘    └───────────┬───────────────────┘
        └──────────────┬───────────────────┘
          ┌────────────▼────────────┐
          │ kynvpn-tunnel           │  pktkit wg::Handler between
          │ (engine, FdTun)         │  the TUN fd and a UDP socket
          └────────────┬────────────┘
          ┌────────────▼────────────┐
          │ kynvpn-core             │  keys, TunnelConfig,
          │                         │  ConfigSource (backend later)
          └─────────────────────────┘
```

- The tunnel never runs in the UI. On Android it lives in our `VpnService`,
  which outlives the activity and is what "always-on VPN" starts at boot. On
  iOS it lives in the Packet Tunnel extension, a separate process.
- Stipple stays a generic UI framework. The VPN platform code (the
  `VpnService` subclass, the `NEPacketTunnelProvider`) belongs to this
  repository; we only ask Stipple for the generic hooks to host it.
- pktkit's `wg::Handler` is used directly, not `wg::Server`/`Adapter`: we own
  the socket (to protect it, and to swap it on network change) and the timer
  loop (for battery).

## Milestones

### M0: Scaffold (done)
Workspace, core model with `wg-quick` import, engine with a localhost
handshake test, Stipple app with a preview controller. Builds for
`aarch64-linux-android` and `aarch64-apple-ios`.

### M1: Engine for production
- [ ] Event-driven timers: sleep until the next WireGuard deadline instead
      of a 100 ms tick (pktkit#12). Replace `FdTun`'s poll timeout with a wake
      pipe at the same time, so an idle tunnel doesn't wake up at all.
- [ ] Counters and last handshake from pktkit once pktkit#13 lands (we keep
      our own until then).
- [ ] Re-resolve the endpoint on network change and on handshake failure;
      endpoint IPv6.
- [ ] Batch reads and writes (`recvmmsg`/`sendmmsg` on Android) if profiling
      on a phone calls for it.
- [ ] A Linux test harness: the engine on a real TUN (pktkit `tuntap`) against
      a real WireGuard server, in CI under a network namespace.

### M2: Android
Blocked on stipple#67 (packaging our Java class) and stipple#68 (JNI and
the consent intent's result).
- [ ] `KynVpnService extends VpnService`: native methods into the `.so`;
      `Builder` from `TunnelConfig` (addresses, routes, DNS, MTU),
      `establish()`, `protect()` the UDP socket, start the engine.
- [ ] Consent: `VpnService.prepare()` and its result.
- [ ] Foreground service notification (type `systemExempted`) with
      "Disconnect"; `onRevoke` (another VPN took over).
- [ ] Network changes in the service (`ConnectivityManager` default network
      callback) → `Tunnel::rebind`.
- [ ] Always-on VPN and lockdown ("Block connections without VPN"): the
      service starts with no activity, from `SERVICE_INTERFACE`.
- [ ] `AndroidVpnControl` in `app/src/vpn.rs`; status from the service.
- [ ] Later: Quick Settings tile (`TileService`, also via stipple#67).

### M3: iOS
Blocked on stipple#69 (building the `.appex`, app groups).
- [ ] Packet Tunnel extension: a Rust executable whose principal class is an
      `NEPacketTunnelProvider` subclass registered with the Objective-C runtime;
      `setTunnelNetworkSettings`, the utun fd (`FdTun::with_af_header`) or
      `packetFlow`, start the engine.
- [ ] `NWPathMonitor` in the extension → `Tunnel::rebind`.
- [ ] `IosVpnControl`: `NETunnelProviderManager` load/save/start/stop,
      status from `NEVPNStatusDidChange`.
- [ ] Configuration handed to the extension through the app group; the
      private key through a shared keychain access group (stipple#70).
- [ ] On-demand rules (the iOS take on always-on); `includeAllNetworks`
      for a kill switch.
- [ ] Testing on physical devices (Network Extensions don't run in the
      simulator).

### M4: Account and servers (backend is still being designed)
- [ ] A `ConfigSource` over the kynvpn API, on `klbfw`: sign-in, server
      list, key registration (our public key in, assigned address and peer
      out).
- [ ] Browser sign-in, coming back through a deep link (stipple#72).
- [ ] Keys and tokens in the Keychain/Keystore (stipple#70); generate the
      WireGuard key on the device, never send the private key.
- [ ] Location picker with latency, favourites.

### M5: Product
- [ ] Settings: kill switch (links to Android's lockdown setting; iOS
      `includeAllNetworks`), custom DNS, per-app split tunnelling on
      Android (`addDisallowedApplication`), LAN access.
- [ ] Offline state in the UI (stipple#71).
- [ ] Import a `wg-quick` file (document picker) for testing and advanced users.
- [ ] Brand assets, localization (the desktop client's languages).
- [ ] Store packaging with `cargo-stipple`, CI for both platforms, signing.

## Upstream tickets

| Ticket | What | Blocks |
|---|---|---|
| [stipple#73](https://github.com/KarpelesLab/stipple/issues/73) | Tracking issue for the items below | |
| [stipple#67](https://github.com/KarpelesLab/stipple/issues/67) | Android: app-supplied Java classes and manifest components | M2 |
| [stipple#68](https://github.com/KarpelesLab/stipple/issues/68) | Android: JNI access, start an intent for a result | M2 |
| [stipple#69](https://github.com/KarpelesLab/stipple/issues/69) | iOS app extensions, app groups | M3 |
| [stipple#70](https://github.com/KarpelesLab/stipple/issues/70) | Secure storage (Keychain, Keystore) | M3, M4 |
| [stipple#71](https://github.com/KarpelesLab/stipple/issues/71) | Network connectivity status and events | M5 |
| [stipple#72](https://github.com/KarpelesLab/stipple/issues/72) | Incoming URLs / deep links | M4 |
| [pktkit-rs#12](https://github.com/KarpelesLab/pktkit-rs/issues/12) | `Handler::next_timer_deadline` | M1 (battery) |
| [pktkit-rs#13](https://github.com/KarpelesLab/pktkit-rs/issues/13) | Per-peer counters, wall-clock last handshake | M1 |
| [pktkit-rs#14](https://github.com/KarpelesLab/pktkit-rs/issues/14) | TUN from an existing fd; android/ios CI | not blocking (we have `FdTun`) |
