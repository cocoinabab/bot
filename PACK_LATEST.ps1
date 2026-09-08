$ErrorActionPreference = 'Stop'
$base = Split-Path -Parent $MyInvocation.MyCommand.Path
$logs = Join-Path $base 'logs'
if (!(Test-Path $logs)) { throw 'logs folder not found.' }
$full = Get-ChildItem $logs -Filter 'full-*.jsonl.gz' -File | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (!$full) { throw 'No full-*.jsonl.gz capture found.' }
$stamp = $full.Name -replace '^full-','' -replace '\.jsonl\.gz$',''
$names = @(
    "decoded-$stamp.log",
    "full-$stamp.jsonl.gz",
    "raw-mcpe-$stamp.jsonl.gz",
    "events-$stamp.jsonl.gz",
    "links-$stamp.jsonl.gz",
    "wire-index-$stamp.jsonl.gz",
    "wire-pre-$stamp.pcap",
    "wire-post-$stamp.pcap"
)
$files = @()
foreach ($n in $names) {
    $p = Join-Path $logs $n
    if (Test-Path $p) { $files += $p }
}
$out = Join-Path $base "BedrockTrafficWatch-capture-$stamp.zip"
if (Test-Path $out) { Remove-Item $out -Force }
Compress-Archive -Path $files -DestinationPath $out -CompressionLevel Optimal
Write-Host "Created: $out"
Write-Host 'private\microsoft-token.json is NOT included.'
