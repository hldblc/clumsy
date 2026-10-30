# Build every shipping variant (x86/x64 x A/B/C) and, with -Zip, package each
# into dist\clumsy-<arch>-<sign>.zip. Run from the repo root:
#   pwsh scripts\build-all.ps1 [-Zig <path-to-zig.exe>] [-Conf Ship] [-Zip]
param(
    [string]$Zig = "zig",
    [ValidateSet("Debug", "Release", "Ship")] [string]$Conf = "Ship",
    [switch]$Zip
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    if ($Zip) { New-Item -ItemType Directory -Force -Path dist | Out-Null }
    foreach ($arch in "x64", "x86") {
        foreach ($sign in "A", "B", "C") {
            Write-Host "== $Conf $arch $sign ==" -ForegroundColor Cyan
            & $Zig build -Dconf=$Conf -Darch=$arch -Dsign=$sign
            if ($LASTEXITCODE -ne 0) { throw "build failed: $arch $sign" }
            if ($Zip) {
                $out = "zig-out\${arch}_${Conf}_${sign}"
                $zipPath = "dist\clumsy-$arch-$sign.zip"
                if (Test-Path $zipPath) { Remove-Item $zipPath }
                Compress-Archive -Path "$out\*" -DestinationPath $zipPath
                Write-Host "packaged $zipPath"
            }
        }
    }
    Write-Host "done" -ForegroundColor Green
} finally {
    Pop-Location
}
