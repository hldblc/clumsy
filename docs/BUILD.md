# Building clumsy

clumsy builds two ways. The zig cross-build is the primary one and produces the
shipping binaries; the CMake/MSVC build is a convenience for Visual Studio
users. Both link the bundled WinDivert and IUP under `external/`.

## Primary: zig 0.9.1

The `build.zig` script uses the zig 0.9-era build API, so it needs **zig 0.9.1**
specifically (newer zig rejects it). Download it from
<https://ziglang.org/download/#release-0.9.1> and either put it on `PATH` or
call it by full path.

From the repo root:

```
zig build                                   # x64 Debug, sign A, into zig-out/x64_Debug_A
zig build test                              # build and run the unit tests
zig build -Dconf=Ship -Darch=x64 -Dsign=A   # a shipping build
```

Options:

| option | values | default |
| --- | --- | --- |
| `-Darch` | `x64`, `x86` | `x64` |
| `-Dconf` | `Debug`, `Release`, `Ship` | `Debug` |
| `-Dsign` | `A`, `B`, `C` (WinDivert driver signature variant) | `A` |
| `-Dwindows_kit_bin_root` | path to a Windows SDK `bin/<ver>` | auto-detected |

The Windows SDK path (for `rc.exe`) is detected automatically: the newest
installed `C:/Program Files (x86)/Windows Kits/10/bin/<ver>` that has `rc.exe`
for the target architecture, or `WindowsSdkVerBinPath` from a Visual Studio
developer prompt, or whatever you pass in `-Dwindows_kit_bin_root`.

Build every shipping variant at once (optionally zip each):

```
pwsh scripts/build-all.ps1 -Zig C:\path\to\zig.exe -Zip
```

## Alternative: CMake + MSVC

Needs Visual Studio (2019 or newer) with the C++ workload and the Windows SDK.
This links the `*_dll16_lib` IUP import libraries and copies the required DLLs,
the driver and `config.txt` next to the executable.

```
cmake -S . -B build -A x64 -DCLUMSY_SIGN=A
cmake --build build --config Release
```

Use `-A Win32` for a 32-bit build. The result is in `build/Release/`.

## Continuous integration

`.github/workflows/ci.yml` runs on every push: it fetches zig 0.9.1 (checksum
verified), runs `zig build test`, builds all six shipping variants
(x86/x64 x A/B/C) and uploads them as an artifact.

## Running

clumsy needs Administrator rights (it loads the WinDivert kernel driver) and
the driver files must sit next to `clumsy.exe` (the build stages them for you).
Launching normally triggers a UAC prompt; from an elevated terminal it starts
directly. See `clumsy --help` for the command line.
