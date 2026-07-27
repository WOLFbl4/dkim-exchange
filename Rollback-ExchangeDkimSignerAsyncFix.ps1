[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BackupDirectory,

    [string]$InstallDir = "C:\Program Files\Exchange DkimSigner"
)

$ErrorActionPreference = "Stop"
$serviceName = "MSExchangeTransport"
$backupProgramDir = Join-Path $BackupDirectory "Program"
$metadataPath = Join-Path $BackupDirectory "metadata.json"
$sourceDll = Join-Path $backupProgramDir "ExchangeDkimSigner.dll"
$sourceSettings = Join-Path $backupProgramDir "settings.xml"
$targetDll = Join-Path $InstallDir "ExchangeDkimSigner.dll"
$targetSettings = Join-Path $InstallDir "settings.xml"

foreach ($requiredPath in $metadataPath, $sourceDll, $sourceSettings) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Rollback file was not found: $requiredPath"
    }
}

$metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
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

Start-Service -Name $serviceName
(Get-Service -Name $serviceName).WaitForStatus("Running", [TimeSpan]::FromMinutes(2))
Start-Sleep -Seconds 10

[pscustomobject]@{
    Status = "RolledBack"
    RestoredDllSha256 = $restoredHash
    TransportService = (Get-Service -Name $serviceName).Status.ToString()
    EdgeTransportPid = (Get-Process -Name EdgeTransport -ErrorAction Stop).Id
} | ConvertTo-Json
