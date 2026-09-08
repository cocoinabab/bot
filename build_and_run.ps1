$ErrorActionPreference = 'Stop'
$base = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $base

function Info([string]$s) { Write-Host "[V7] $s" }

# Reuse WinDivert automatically from V3/V4/V5/V6 when possible.
$dll = Join-Path $base 'WinDivert.dll'
$sys = Join-Path $base 'WinDivert64.sys'
if (!(Test-Path $dll) -or !(Test-Path $sys)) {
    Info 'Looking automatically for existing WinDivert.dll / WinDivert64.sys ...'
    $roots = @((Split-Path -Parent $base), [Environment]::GetFolderPath('Desktop'), (Join-Path $env:USERPROFILE 'Downloads')) | Select-Object -Unique
    foreach ($root in $roots) {
        if (!(Test-Path $root)) { continue }
        $foundDll = Get-ChildItem -Path $root -Filter 'WinDivert.dll' -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($foundDll) {
            $candidateSys = Join-Path $foundDll.Directory.FullName 'WinDivert64.sys'
            if (Test-Path $candidateSys) {
                Copy-Item $foundDll.FullName $dll -Force
                Copy-Item $candidateSys $sys -Force
                Info "Copied WinDivert automatically from $($foundDll.Directory.FullName)"
                break
            }
        }
    }
}
if (!(Test-Path $dll) -or !(Test-Path $sys)) {
    throw 'WinDivert.dll / WinDivert64.sys not found. Put the pair beside START_V7_ULTIMATE.cmd, then run again.'
}

$exe = Join-Path $base 'BedrockTrafficWatch-v7-ULTIMATE.exe'
if (!(Test-Path $exe)) {
    Info 'First build only: preparing Go toolchain. Minecraft server settings will NOT be changed.'
    $toolRoot = Join-Path $base '_toolchain'
    $goRoot = Join-Path $toolRoot 'go'
    $goExe = Join-Path $goRoot 'bin\go.exe'
    New-Item -ItemType Directory -Path $toolRoot -Force | Out-Null

    # Prefer a sibling V6/V5 portable Go installation to avoid another 71 MB download.
    if (!(Test-Path $goExe)) {
        $roots = @((Split-Path -Parent $base), [Environment]::GetFolderPath('Desktop'), (Join-Path $env:USERPROFILE 'Downloads')) | Select-Object -Unique
        foreach ($root in $roots) {
            if (!(Test-Path $root)) { continue }
            $foundGo = Get-ChildItem -Path $root -Filter 'go.exe' -File -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -match '[\\/]_toolchain[\\/]go[\\/]bin[\\/]go\.exe$' } |
                Select-Object -First 1
            if ($foundGo) {
                $goExe = $foundGo.FullName
                $goRoot = Split-Path -Parent (Split-Path -Parent $goExe)
                Info "Reusing portable Go from $goRoot"
                break
            }
        }
    }

    if (!(Test-Path $goExe)) {
        $goRoot = Join-Path $toolRoot 'go'
        $goExe = Join-Path $goRoot 'bin\go.exe'
        $goZip = Join-Path $toolRoot 'go1.26.5.windows-amd64.zip'
        $goUrl = 'https://go.dev/dl/go1.26.5.windows-amd64.zip'
        $expected = '97e6b2a833b6d89f9ff17d25419ac0a7e3b482a044e9ab18cdef834bd834fd38'
        Info 'Downloading official Go 1.26.5 portable ZIP (~71 MB) ...'
        Invoke-WebRequest -UseBasicParsing -Uri $goUrl -OutFile $goZip
        $actual = (Get-FileHash -Algorithm SHA256 $goZip).Hash.ToLowerInvariant()
        if ($actual -ne $expected) {
            Remove-Item $goZip -Force -ErrorAction SilentlyContinue
            throw "Go ZIP SHA256 mismatch. Expected $expected, got $actual"
        }
        if (Test-Path $goRoot) { Remove-Item $goRoot -Recurse -Force }
        Expand-Archive -Path $goZip -DestinationPath $toolRoot -Force
        Info 'Go toolchain ready.'
    }

    $env:GOROOT = $goRoot
    $env:PATH = "$($goRoot)\bin;$env:PATH"
    $env:GOPATH = Join-Path $base '_gopath'
    $env:GOMODCACHE = Join-Path $env:GOPATH 'pkg\mod'
    $env:GOCACHE = Join-Path $base '_gocache'
    $env:GOPROXY = 'https://proxy.golang.org,direct'
    $env:CGO_ENABLED = '0'

    Info (& $goExe version)
    Info 'Resolving gophertunnel v1.59.0 dependencies ...'
    & $goExe mod tidy
    if ($LASTEXITCODE -ne 0) { throw "go mod tidy failed with exit code $LASTEXITCODE" }

    Info 'Building BedrockTrafficWatch-v7-ULTIMATE.exe ...'
    & $goExe build -mod=mod -trimpath -ldflags '-s -w' -o $exe .
    if ($LASTEXITCODE -ne 0 -or !(Test-Path $exe)) { throw "go build failed with exit code $LASTEXITCODE" }
    Info 'Build complete. Future starts skip build/download steps.'
}

Info 'Starting V7 ULTIMATE as Administrator ...'
$p = Start-Process -FilePath $exe -WorkingDirectory $base -Verb RunAs -PassThru
$p.WaitForExit()
