[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BackupDirectory,

    [string]$InstallDir
)

$ErrorActionPreference = "Stop"
$serviceName = "MSExchangeTransport"
$backupProgramDir = Join-Path $BackupDirectory "Program"
$metadataPath = Join-Path $BackupDirectory "metadata.json"

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "An elevated administrator session is required."
}

if (-not (Test-Path -LiteralPath $metadataPath -PathType Leaf)) {
    throw "Rollback metadata was not found: $metadataPath"
}

$metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    $InstallDir = [string]$metadata.InstallDir
}
if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    throw "InstallDir was not supplied and is missing from rollback metadata."
}

$sourceDll = Join-Path $backupProgramDir "ExchangeDkimSigner.dll"
$sourceSettings = Join-Path $backupProgramDir "settings.xml"
$targetDll = Join-Path $InstallDir "ExchangeDkimSigner.dll"
$targetSettings = Join-Path $InstallDir "settings.xml"

foreach ($requiredPath in $sourceDll, $sourceSettings) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Rollback file was not found: $requiredPath"
    }
}

$sourceHash = (Get-FileHash -LiteralPath $sourceDll -Algorithm SHA256).Hash
if ($sourceHash -ne $metadata.OriginalDllSha256) {
    throw "Backup DLL hash does not match the metadata. Rollback was not started."
}
$sourceSettingsHash = (Get-FileHash -LiteralPath $sourceSettings -Algorithm SHA256).Hash
if ($metadata.PSObject.Properties.Name -contains "OriginalSettingsSha256" -and
    $sourceSettingsHash -ne $metadata.OriginalSettingsSha256) {
    throw "Backup settings.xml hash does not match the metadata. Rollback was not started."
}

$service = Get-Service -Name $serviceName
if ($service.Status -ne "Stopped") {
    Stop-Service -Name $serviceName -Force
    $service.WaitForStatus("Stopped", [TimeSpan]::FromMinutes(2))
}

Copy-Item -LiteralPath $sourceDll -Destination $targetDll -Force
Copy-Item -LiteralPath $sourceSettings -Destination $targetSettings -Force

$restoredHash = (Get-FileHash -LiteralPath $targetDll -Algorithm SHA256).Hash
if ($restoredHash -ne $metadata.OriginalDllSha256) {
    throw "Restored DLL hash does not match the backup metadata."
}
$restoredSettingsHash = (Get-FileHash -LiteralPath $targetSettings -Algorithm SHA256).Hash
if ($metadata.PSObject.Properties.Name -contains "OriginalSettingsSha256" -and
    $restoredSettingsHash -ne $metadata.OriginalSettingsSha256) {
    throw "Restored settings.xml hash does not match the backup metadata."
}

$originalServiceStatus = [string]$metadata.OriginalServiceStatus
switch ($originalServiceStatus) {
    { $_ -in "Running", "StartPending", "ContinuePending" } {
        Start-Service -Name $serviceName
        (Get-Service -Name $serviceName).WaitForStatus("Running", [TimeSpan]::FromMinutes(2))
        break
    }
    { $_ -in "Paused", "PausePending" } {
        Start-Service -Name $serviceName
        (Get-Service -Name $serviceName).WaitForStatus("Running", [TimeSpan]::FromMinutes(2))
        Suspend-Service -Name $serviceName
        (Get-Service -Name $serviceName).WaitForStatus("Paused", [TimeSpan]::FromMinutes(2))
        break
    }
}

if ((Get-Service -Name $serviceName).Status -eq "Running") {
    Start-Sleep -Seconds 10
}

$edgeProcess = Get-Process -Name EdgeTransport -ErrorAction SilentlyContinue
$edgeTransportPid = if ($null -ne $edgeProcess) { $edgeProcess.Id } else { $null }

[pscustomobject]@{
    Status = "RolledBack"
    RestoredDllSha256 = $restoredHash
    RestoredSettingsSha256 = $restoredSettingsHash
    InstallDir = $InstallDir
    TransportService = (Get-Service -Name $serviceName).Status.ToString()
    EdgeTransportPid = $edgeTransportPid
} | ConvertTo-Json
