[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PatchDll,

    [Parameter(Mandatory = $true)]
    [string]$RollbackScript,

    [string]$InstallDir = "C:\Program Files\Exchange DkimSigner",
    [string]$BackupRoot = "C:\ProgramData\ExchangeDkimSigner\Backups"
)

$ErrorActionPreference = "Stop"
$serviceName = "MSExchangeTransport"
$targetDll = Join-Path $InstallDir "ExchangeDkimSigner.dll"
$settingsPath = Join-Path $InstallDir "settings.xml"
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$backupDir = Join-Path $BackupRoot $timestamp
$backupProgramDir = Join-Path $backupDir "Program"
$changeStarted = Get-Date
$targetChanged = $false

function Set-RestrictedDirectoryAcl {
    param([Parameter(Mandatory = $true)][string]$Path)

    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sidValue in "S-1-5-18", "S-1-5-32-544") {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($sidValue)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit",
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        [void]$acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Restore-OriginalFiles {
    $service = Get-Service -Name $serviceName
    if ($service.Status -ne "Stopped") {
        Stop-Service -Name $serviceName -Force
        $service.WaitForStatus("Stopped", [TimeSpan]::FromMinutes(2))
    }

    Copy-Item -LiteralPath (Join-Path $backupProgramDir "ExchangeDkimSigner.dll") -Destination $targetDll -Force
    Copy-Item -LiteralPath (Join-Path $backupProgramDir "settings.xml") -Destination $settingsPath -Force

    Start-Service -Name $serviceName
    (Get-Service -Name $serviceName).WaitForStatus("Running", [TimeSpan]::FromMinutes(2))
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "An elevated administrator session is required."
}

foreach ($requiredPath in $PatchDll, $RollbackScript, $targetDll, $settingsPath) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Required file was not found: $requiredPath"
    }
}

$patchIdentity = [Reflection.AssemblyName]::GetAssemblyName($PatchDll)
if ($patchIdentity.Name -ne "ExchangeDkimSigner" -or $patchIdentity.Version.ToString() -ne "3.4.0.0") {
    throw "Unexpected patch assembly identity: $($patchIdentity.FullName)"
}

$patchAssembly = [Reflection.Assembly]::ReflectionOnlyLoadFrom($PatchDll)
$patchReferences = @{}
foreach ($reference in $patchAssembly.GetReferencedAssemblies()) {
    $patchReferences[$reference.Name] = $reference.Version.ToString()
}
$expectedReferences = @{
    "BouncyCastle.Crypto" = "1.8.10.0"
    "MimeKit" = "2.15.0.0"
    "Microsoft.Exchange.Data.Common" = "15.0.1474.0"
    "Microsoft.Exchange.Data.Transport" = "15.0.1474.0"
}
foreach ($name in $expectedReferences.Keys) {
    if ($patchReferences[$name] -ne $expectedReferences[$name]) {
        throw "Unexpected reference $name version: $($patchReferences[$name])"
    }
}

New-Item -Path $backupProgramDir -ItemType Directory -Force | Out-Null
Set-RestrictedDirectoryAcl -Path $backupDir
Copy-Item -LiteralPath $InstallDir -Destination $backupProgramDir -Recurse -Force
Copy-Item -LiteralPath $RollbackScript -Destination (Join-Path $backupDir "Rollback-ExchangeDkimSignerAsyncFix.ps1") -Force

$originalHash = (Get-FileHash -LiteralPath $targetDll -Algorithm SHA256).Hash
$patchHash = (Get-FileHash -LiteralPath $PatchDll -Algorithm SHA256).Hash
$metadata = [ordered]@{
    Created = (Get-Date).ToString("o")
    Computer = $env:COMPUTERNAME
    InstallDir = $InstallDir
    OriginalDllSha256 = $originalHash
    PatchDllSha256 = $patchHash
    OriginalServiceStatus = (Get-Service -Name $serviceName).Status.ToString()
}
$metadata | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $backupDir "metadata.json") -Encoding UTF8

$rollbackCommand = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$backupDir\Rollback-ExchangeDkimSignerAsyncFix.ps1`" -BackupDirectory `"$backupDir`""
$rollbackCommand | Set-Content -LiteralPath (Join-Path $backupDir "ROLLBACK-COMMAND.txt") -Encoding ASCII

try {
    $service = Get-Service -Name $serviceName
    if ($service.Status -ne "Stopped") {
        Stop-Service -Name $serviceName -Force
        $service.WaitForStatus("Stopped", [TimeSpan]::FromMinutes(2))
    }

    Copy-Item -LiteralPath $PatchDll -Destination $targetDll -Force
    $targetChanged = $true

    [xml]$settings = Get-Content -LiteralPath $settingsPath -Raw
    $headerChanged = $false
    foreach ($node in @($settings.SelectNodes("/Settings/HeadersToSign/string"))) {
        if ($node.InnerText -eq "Message-ID") {
            $node.InnerText = "MessageId"
            $headerChanged = $true
        }
    }
    if ($headerChanged) {
        $settings.Save($settingsPath)
    }

    Start-Service -Name $serviceName
    (Get-Service -Name $serviceName).WaitForStatus("Running", [TimeSpan]::FromMinutes(2))
    Start-Sleep -Seconds 20

    if ((Get-Service -Name $serviceName).Status -ne "Running") {
        throw "$serviceName did not remain running."
    }
    if (-not (Get-Process -Name EdgeTransport -ErrorAction SilentlyContinue)) {
        throw "EdgeTransport process was not found after service start."
    }

    $dkimErrors = @(Get-WinEvent -FilterHashtable @{ LogName = "Application"; StartTime = $changeStarted } -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Level -le 2 -and
            $_.ProviderName -in "Exchange DKIM", "MSExchange Extensibility" -and
            $_.Message -match "(?i)DKIM"
        })
    if ($dkimErrors.Count -gt 0) {
        throw "DKIM-related errors were logged after deployment: $($dkimErrors.Count)"
    }

    [pscustomobject]@{
        Status = "Deployed"
        BackupDirectory = $backupDir
        RollbackCommand = $rollbackCommand
        OriginalDllSha256 = $originalHash
        InstalledDllSha256 = (Get-FileHash -LiteralPath $targetDll -Algorithm SHA256).Hash
        HeaderChangedToMessageId = $headerChanged
        TransportService = (Get-Service -Name $serviceName).Status.ToString()
        EdgeTransportPid = (Get-Process -Name EdgeTransport).Id
    } | ConvertTo-Json -Depth 3
}
catch {
    $deploymentError = $_
    if ($targetChanged) {
        Restore-OriginalFiles
    }
    throw "Deployment failed and original files were restored: $($deploymentError.Exception.Message)"
}
