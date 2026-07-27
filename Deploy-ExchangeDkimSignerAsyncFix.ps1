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
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss-fff"
$backupDir = Join-Path $BackupRoot $timestamp
$backupProgramDir = Join-Path $backupDir "Program"
$changeStarted = Get-Date
$targetChanged = $false
$originalServiceStatus = $null

function Set-RestrictedDirectoryAcl {
    [CmdletBinding(SupportsShouldProcess = $true)]
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
    if ($PSCmdlet.ShouldProcess($Path, "Set restricted backup directory ACL")) {
        Set-Acl -LiteralPath $Path -AclObject $acl
    }
}

function Restore-OriginalFile {
    $service = Get-Service -Name $serviceName
    if ($service.Status -ne "Stopped") {
        Stop-Service -Name $serviceName -Force
        $service.WaitForStatus("Stopped", [TimeSpan]::FromMinutes(2))
    }

    if ($targetChanged) {
        Copy-Item -LiteralPath (Join-Path $backupProgramDir "ExchangeDkimSigner.dll") -Destination $targetDll -Force
        Copy-Item -LiteralPath (Join-Path $backupProgramDir "settings.xml") -Destination $settingsPath -Force

        $restoredHash = (Get-FileHash -LiteralPath $targetDll -Algorithm SHA256).Hash
        if ($restoredHash -ne $originalHash) {
            throw "Restored DLL hash does not match the original file."
        }
        $restoredSettingsHash = (Get-FileHash -LiteralPath $settingsPath -Algorithm SHA256).Hash
        if ($restoredSettingsHash -ne $originalSettingsHash) {
            throw "Restored settings.xml hash does not match the original file."
        }
    }

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

$originalHash = (Get-FileHash -LiteralPath $targetDll -Algorithm SHA256).Hash
$originalSettingsHash = (Get-FileHash -LiteralPath $settingsPath -Algorithm SHA256).Hash
$patchHash = (Get-FileHash -LiteralPath $PatchDll -Algorithm SHA256).Hash
$originalServiceStatus = (Get-Service -Name $serviceName).Status.ToString()

New-Item -Path $backupProgramDir -ItemType Directory -Force | Out-Null
Set-RestrictedDirectoryAcl -Path $backupDir
Copy-Item -LiteralPath $targetDll -Destination (Join-Path $backupProgramDir "ExchangeDkimSigner.dll") -Force
Copy-Item -LiteralPath $settingsPath -Destination (Join-Path $backupProgramDir "settings.xml") -Force
Copy-Item -LiteralPath $RollbackScript -Destination (Join-Path $backupDir "Rollback-ExchangeDkimSignerAsyncFix.ps1") -Force

if ((Get-FileHash -LiteralPath (Join-Path $backupProgramDir "ExchangeDkimSigner.dll") -Algorithm SHA256).Hash -ne $originalHash -or
    (Get-FileHash -LiteralPath (Join-Path $backupProgramDir "settings.xml") -Algorithm SHA256).Hash -ne $originalSettingsHash) {
    throw "Backup verification failed. Deployment was not started."
}

$metadata = [ordered]@{
    Created = (Get-Date).ToString("o")
    Computer = $env:COMPUTERNAME
    InstallDir = $InstallDir
    OriginalDllSha256 = $originalHash
    OriginalSettingsSha256 = $originalSettingsHash
    PatchDllSha256 = $patchHash
    OriginalServiceStatus = $originalServiceStatus
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

    $targetChanged = $true
    Copy-Item -LiteralPath $PatchDll -Destination $targetDll -Force

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
    try {
        Restore-OriginalFile
    }
    catch {
        $restoreError = $_
        throw "Deployment failed: $($deploymentError.Exception.Message) Automatic restore also failed: $($restoreError.Exception.Message) Use the rollback script in '$backupDir'."
    }

    throw "Deployment failed and the original state was restored: $($deploymentError.Exception.Message)"
}
