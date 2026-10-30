# clumsy fork roadmap

25 planned features, in implementation order (dependencies first).
Status: [ ] planned, [~] in progress, [x] done.

## Foundation (engine refactors that later items depend on)

- [x] 25a. Build: Windows SDK auto-detect, `zig build test` unit tests (534 checks), source list dedup
- [x] 24. Memory pool for packets, lock-free capture-to-processor hand-off, max kernel queue
- [x] 2. High-resolution scheduler: waitable timer armed for the earliest pending release
- [x] 12. Per-flow state: flow hash on every packet, "apply to N% of flows" scope on every module
- [x] 16. Multiple rule sets: several filters, each with its own module chain, first match wins

## Impairment engine

- [x] 1. Lag jitter and latency distributions (uniform, normal, heavy-tailed) with keep-order option
- [x] 3. Burst loss with a two-state Gilbert-Elliott model
- [x] 4. Real bandwidth shaping: token bucket + queue, tail/head/random-early drop, bufferbloat
- [x] 5. Asymmetric per-direction values on every module
- [x] 8. Richer corruption modes: xor, bit flips, zero-fill, truncate; payload/all region; redo/leave/corrupt checksum
- [x] 10. TCP-aware impairments: SYN drop, pure-ACK drop, retransmit delay, window clamp, SYN option strip
- [x] 11. Outages and link flapping (periodic or random, silent drop while down)
- [x] 9. Fragmentation and MTU stress (IPv4 split into fragments, optional fragment loss)

## Targeting and automation

- [x] 14. Live filter validation (as-you-type valid/invalid indicator) and a Build... filter builder
- [x] 15. Hostname/CIDR targets: Build dialog resolves a host, IP or CIDR into a filter clause (re-resolve needs restart)
- [x] 13. Per-process filtering via the WinDivert flow layer (Process field per rule)
- [x] 17. Real command line: --help/--version/--list, --seed, --load, --profile, --start, --headless, plus classic --module-param
- [x] 6. Link profiles (3G, LTE, satellite, DSL bufferbloat, lossy Wi-Fi, flapping, ...) applied to the current rule
- [x] 19. Saved sessions and shareable configs (Save/Load to .clumsy INI-style files)
- [x] 7. Scripted scenarios on a timeline (Load/Play, progress, looping; etc/scenario-example.txt)
- [x] 18. Remote control API (loopback HTTP+JSON, token-gated; --api on --api-port --api-token)
- [x] 20. Global hotkeys (F5/F6/Ctrl+Alt+F12 panic) and minimize-to-tray with a menu

## Observability, safety and platform

- [x] 21. Live statistics window: engine + per-module counters, rolling throughput graph, CSV export
- [x] 22. Packet log and pcapng export (per-packet action comments, opens in Wireshark)
- [x] 23. Safety: panic restore, stall watchdog that reopens the link, driver diagnose/remove-service
- [x] 25b. CI (GitHub Actions, all 6 variants), CMake/MSVC build, build-all packaging script, docs/BUILD.md (WinDivert 2.2.0 is current; ARM64 not attempted)
