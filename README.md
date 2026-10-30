# clumsy

__clumsy makes your network condition on Windows significantly worse, but in a managed and interactive manner.__

Leveraging the awesome [WinDivert](https://reqrypt.org/windivert.html), clumsy stops living network packets and captures them, lag/drop/tamper/.. the packets on demand, then sends them away. Whether you want to track down weird bugs related to a broken network, or evaluate your application on poor connections, clumsy will come in handy:

* No installation.
* No need for proxy setup or code change in your application.
* System-wide network capturing means it works on any application.
* Works even if you're offline (ie, connecting from localhost to localhost).
* Your application keeps running, while clumsy can start and stop anytime.
* Interactive control of how bad the network can be, with enough visual feedback to tell you what's going on.

This is an actively developed fork of [jagt/clumsy](https://github.com/jagt/clumsy). See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the full feature list and status.

![](clumsy-demo.gif)

## What this fork adds

The packet engine was rebuilt around a lock-free capture-to-processor hand-off, a pooled allocator, and a high-resolution scheduler, so latency timing is accurate and UDP bursts no longer starve the capture thread. On top of that:

* **Multiple rules.** Several filters at once, each on its own tab with its own module chain; a packet is handled by the first rule it matches.
* **Per-process and host/CIDR targeting.** Scope a rule to one executable (via the WinDivert flow layer) or build a filter from a hostname, IP or CIDR block.
* **Richer impairments.** Lag with jitter and uniform/normal/heavy-tailed distributions and keep-order; bursty (Gilbert-Elliott) packet loss; a real token-bucket-style bandwidth shaper with a queue (bufferbloat) or a policer; out-of-order; duplicate; tamper with xor/bit-flip/zero/truncate and a checksum policy; TCP-aware drops/retransmit-delay/window-clamp/option-strip; periodic or random outages; and IPv4 fragmentation.
* **Per-direction values.** Every rate and delay can differ inbound vs outbound (type `20/80`, or use the Advanced row).
* **Profiles, sessions and scenarios.** One-click link profiles (3G, LTE, satellite, DSL bufferbloat, flaky Wi-Fi, ...), save/load `.clumsy` configs, and scripted timelines that change conditions over time.
* **Live filter validation and a builder**, a **statistics window** with a rolling throughput graph and CSV export, and **pcapng logging** with per-packet action comments for Wireshark.
* **Automation and control.** A real command line (`--help`, `--list`, profiles, seed, headless), a token-gated loopback HTTP/JSON API, global hotkeys (F5/F6, Ctrl+Alt+F12 panic) and minimize-to-tray.
* **Safety.** A panic hotkey that restores the network at once, a watchdog that reopens the link if the processor stalls, and driver diagnose/remove-service tools for the common "failed to open device" errors.

## Building

See [`docs/BUILD.md`](docs/BUILD.md). In short: `zig build` with **zig 0.9.1** (primary), or `cmake -S . -B build -A x64 && cmake --build build --config Release` with Visual Studio.

clumsy must run as Administrator (it loads the WinDivert driver). Run `clumsy --help` for the command line.

## License

MIT. Bundled WinDivert and IUP keep their own licenses (see `external/`).
