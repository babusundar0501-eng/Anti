# Run in PowerShell: .\persistence_guard.ps1
$RunKeys = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

function Get-StartupSnapshot {
    $snapshot = @{}
    foreach ($key in $RunKeys) {
        if (Test-Path $key) {
            $props = Get-ItemProperty -Path $key
            $props.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
                $snapshot["$key\$($_.Name)"] = $_.Value
            }
        }
    }
    return $snapshot
}

Write-Host "[PERSISTENCE-GUARD] Taking baseline startup snapshot..." -ForegroundColor Cyan
$baseline = Get-StartupSnapshot

while ($true) {
    Start-Sleep -Seconds 3
    $current = Get-StartupSnapshot

    foreach ($entry in $current.Keys) {
        if (-not $baseline.ContainsKey($entry)) {
            Write-Host "[PERSISTENCE ALERT] New Startup Entry Detected!" -ForegroundColor Red
            Write-Host "  Key:   $entry" -ForegroundColor Yellow
            Write-Host "  Value: $($current[$entry])" -ForegroundColor Yellow
            $baseline[$entry] = $current[$entry]
        }
    }
}
