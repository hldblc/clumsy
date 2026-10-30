# clumsy fork roadmap

25 planned features, in implementation order (dependencies first).
Status: [ ] planned, [~] in progress, [x] done.

## Foundation (engine refactors that later items depend on)

- [ ] 25a. Build: auto-detect Windows SDK, unit-test target, CI, CMake for MSVC, newer WinDivert
- [ ] 24. Memory pool for packets, lock-free capture-to-processor hand-off, max kernel queue
- [ ] 2. High-resolution scheduler: waitable timer armed for the earliest pending release
- [ ] 12. Per-flow state: flow hash on every packet, "apply to N% of flows" scope on every module
- [ ] 16. Multiple rule sets: several filters, each with its own module chain, first match wins

## Impairment engine

- [ ] 1. Lag jitter and latency distributions (uniform, normal, heavy-tailed) with keep-order option
- [ ] 3. Burst loss with a two-state Gilbert-Elliott model
- [ ] 4. Real bandwidth shaping: token bucket + queue, tail/head/random-early drop, bufferbloat
- [ ] 5. Asymmetric per-direction values on every module
- [ ] 8. Richer corruption modes: bit flips, truncate, zero-fill, header/payload, checksum policy
- [x] 10. TCP-aware impairments: SYN drop, pure-ACK drop, retransmit delay, window clamp, SYN option strip
- [x] 11. Outages and link flapping (periodic or random, silent drop while down)
- [x] 9. Fragmentation and MTU stress (IPv4 split into fragments, optional fragment loss)

## Targeting and automation

- [x] 14. Live filter validation (as-you-type valid/invalid indicator) and a Build... filter builder
- [~] 15. Hostname/CIDR targets (CIDR can be written directly in filters; hostname resolution pending)
- [x] 13. Per-process filtering via the WinDivert flow layer (Process field per rule)
- [ ] 17. Real command line: help, validation, profiles, scenarios, seed, headless
- [ ] 6. Link profiles (3G, LTE, satellite, lossy Wi-Fi, DSL, intercontinental)
- [ ] 19. Saved sessions and shareable JSON configs
- [ ] 7. Scripted scenarios on a timeline
- [ ] 18. Remote control API (local HTTP + JSON, token protected)
- [ ] 20. Global hotkeys and tray mode

## Observability, safety and platform

- [ ] 21. Live statistics and graphs
- [ ] 22. Packet log and pcapng export
- [ ] 23. Safety and recovery hardening: crash flush, diagnostics, driver service control
- [ ] 25b. CI, CMake, release packaging
