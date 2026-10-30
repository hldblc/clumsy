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
- [x] 8. Richer corruption modes: xor, bit flips, zero-fill, truncate; payload/all region; redo/leave/corrupt checksum
- [x] 10. TCP-aware impairments: SYN drop, pure-ACK drop, retransmit delay, window clamp, SYN option strip
- [x] 11. Outages and link flapping (periodic or random, silent drop while down)
- [x] 9. Fragmentation and MTU stress (IPv4 split into fragments, optional fragment loss)

## Targeting and automation

- [x] 14. Live filter validation (as-you-type valid/invalid indicator) and a Build... filter builder
- [~] 15. Hostname/CIDR targets (CIDR can be written directly in filters; hostname resolution pending)
- [x] 13. Per-process filtering via the WinDivert flow layer (Process field per rule)
- [x] 17. Real command line: --help/--version/--list, --seed, --load, --profile, --start, --headless, plus classic --module-param
- [x] 6. Link profiles (3G, LTE, satellite, DSL bufferbloat, lossy Wi-Fi, flapping, ...) applied to the current rule
- [x] 19. Saved sessions and shareable configs (Save/Load to .clumsy INI-style files)
- [x] 7. Scripted scenarios on a timeline (Load/Play, progress, looping; etc/scenario-example.txt)
- [ ] 18. Remote control API (local HTTP + JSON, token protected)
- [ ] 20. Global hotkeys and tray mode

## Observability, safety and platform

- [x] 21. Live statistics window: engine + per-module counters, rolling throughput graph, CSV export
- [x] 22. Packet log and pcapng export (per-packet action comments, opens in Wireshark)
- [ ] 23. Safety and recovery hardening: crash flush, diagnostics, driver service control
- [ ] 25b. CI, CMake, release packaging
