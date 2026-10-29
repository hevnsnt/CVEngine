<#
.SYNOPSIS
    cvengine-inventory.ps1: tell cvENGINE what this Windows machine is.

.DESCRIPTION
    Collects the exact Windows build (including the update revision), installed updates, installed software, installed roles and
    features, listening ports, running services and a few security settings, and POSTs them as "inventory v1" JSON over HTTPS to
    cvENGINE. cvENGINE scans from outside and cannot see any of this: with it, local-only and privilege-escalation CVEs become
    decidable and software versions stop being guesses. Windows PowerShell 5.1 and PowerShell 7, on Windows.

    Read-only: it only reads (CIM classes, the registry, the Windows Update Agent's local history, network and service listings) and
    never installs, changes or deletes anything. It does not query the Windows Update service or any server for pending updates, and
    it does not use Get-Package (which can bootstrap package providers). It never reads or sends passwords, keys, tokens, files,
    event logs, shell history or environment variables. The machine's id is sent only as sha256("cvengine-inventory-v1:" + MachineGuid).

    The bearer token comes from the CVENGINE_TOKEN environment variable or -TokenFile and is deliberately NOT a parameter: parameters
    are visible in process listings and are saved by PSReadLine in the console history; an environment variable or an access-restricted
    file are not.

    Exit codes: 0 sent (or dry run), 1 bad usage or configuration, 2 nothing could be collected, 3 could not reach the server or its
    certificate is not trusted, 4 the server refused the report (read its message), 5 the server kept failing.

.PARAMETER Server
    cvENGINE address, https only (or CVENGINE_URL).
.PARAMETER Project
    Project slug to report to (or CVENGINE_PROJECT).
.PARAMETER TokenFile
    File whose first line is the token (or CVENGINE_TOKEN_FILE). Restrict it to SYSTEM and Administrators.
.PARAMETER CaFile
    PEM file of the certificate authority that signed the server (the installer's secrets\certs\ca.crt).
.PARAMETER Insecure
    DO NOT VERIFY THE SERVER'S CERTIFICATE. Anyone on the network path can read the token and the report. Testing only.
.PARAMETER DryRun
    Print the report that would be sent and send nothing. Needs no token.
.PARAMETER IncludeMacs
    Include network interface MAC addresses (off by default).
.PARAMETER Schedule
    Print (do not apply) a scheduled task that runs this daily, then exit.

.EXAMPLE
    $env:CVENGINE_TOKEN = Get-Content C:\ProgramData\cvENGINE\inventory.token
    .\cvengine-inventory.ps1 -Server https://cvengine.example.test -Project my-project -CaFile C:\ProgramData\cvENGINE\ca.crt
#>
[CmdletBinding()]
param(
    [string]$Server = $env:CVENGINE_URL,
    [string]$Project = $env:CVENGINE_PROJECT,
    [string]$TokenFile = $env:CVENGINE_TOKEN_FILE,
    [string]$CaFile = '',
    [switch]$Insecure,
    [switch]$DryRun,
    [switch]$IncludeMacs,
    [ValidateRange(1, 300)][int]$TimeoutSec = 30,
    [ValidateRange(0, 10)][int]$Retries = 3,
    [switch]$Schedule,
    [switch]$Version
)

Set-StrictMode -Version 1.0
$ErrorActionPreference = 'Stop'
$ScriptName = 'cvengine-inventory.ps1'
$ScriptVersion = '1.0.0'

function Write-Info([string]$Message) { [Console]::Error.WriteLine("cvengine-inventory: $Message") }

class Failure : System.Exception {
    [int]$Code
    Failure([int]$Code, [string]$Message) : base($Message) { $this.Code = $Code }
}

# --- small helpers ---------------------------------------------------------------------------------------------------------

function Clean([object]$Value, [int]$Limit = 200) {
    if ($null -eq $Value) { return '' }
    $text = [regex]::Replace([string]$Value, '[\x00-\x1f\x7f]', ' ').Trim()
    if ($text.Length -gt $Limit) { $text = $text.Substring(0, $Limit) }
    return $text
}

function Prop([object]$Object, [string]$Name) {
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}

function Utc([object]$Time) {
    if ($null -eq $Time) { return '' }
    try { return ([datetime]$Time).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [System.Globalization.CultureInfo]::InvariantCulture) } catch { return '' }
}

function Day([object]$Time) {
    try { return ([datetime]$Time).ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture) } catch { return '' }
}

function Sha256Hex([string]$Text) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return (($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text)) | ForEach-Object { $_.ToString('x2') }) -join '') }
    finally { $sha.Dispose() }
}

# a collector that fails costs only its own part of the report, not the whole report
# (the leading commas keep an array an array: a function's output would otherwise be unrolled into the pipeline)
function Try-Collect([string]$What, [scriptblock]$Block, $Default) {
    try { return , (& $Block) } catch { Write-Info "could not collect $What ($($_.Exception.Message))"; return , $Default }
}

# --- the scheduling snippet (nothing is registered) ------------------------------------------------------------------------

function Show-Schedule {
    $url = if ($Server) { $Server } else { 'https://cvengine.example.test' }
    $proj = if ($Project) { $Project } else { 'my-project' }
    @"
# Nothing has been registered. Copy what you want, in an elevated PowerShell.
# 1. Put the script and the token where only SYSTEM and Administrators can read them:
New-Item -ItemType Directory -Force 'C:\ProgramData\cvENGINE' | Out-Null
Copy-Item .\$ScriptName 'C:\ProgramData\cvENGINE\'
Set-Content 'C:\ProgramData\cvENGINE\inventory.token' '<paste the token here>'
icacls 'C:\ProgramData\cvENGINE' /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F'

# 2. A daily scheduled task, with up to an hour of random delay so a fleet does not report in the same second:
`$arguments = '-NoProfile -ExecutionPolicy Bypass -File "C:\ProgramData\cvENGINE\$ScriptName" -Server $url -Project $proj -TokenFile "C:\ProgramData\cvENGINE\inventory.token" -CaFile "C:\ProgramData\cvENGINE\ca.crt"'
`$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument `$arguments
`$trigger = New-ScheduledTaskTrigger -Daily -At 3am -RandomDelay (New-TimeSpan -Hours 1)
Register-ScheduledTask -TaskName 'cvENGINE inventory' -Action `$action -Trigger `$trigger -User 'SYSTEM' -RunLevel Highest
"@
}

# --- collecting ------------------------------------------------------------------------------------------------------------

function Get-Addresses {
    $found = New-Object System.Collections.Generic.List[string]
    foreach ($nic in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        if ($nic.OperationalStatus -ne 'Up' -or $nic.NetworkInterfaceType -eq 'Loopback') { continue }
        foreach ($unicast in $nic.GetIPProperties().UnicastAddresses) {
            $address = ($unicast.Address.IPAddressToString -split '%')[0]
            if ($address -and $address -notmatch '^(127\.|::1$|fe80:|169\.254\.)' -and -not $found.Contains($address)) { $found.Add($address) }
        }
    }
    return , $found.ToArray()
}

function Get-MacAddresses {
    $found = New-Object System.Collections.Generic.List[string]
    foreach ($nic in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        if ($nic.NetworkInterfaceType -eq 'Loopback') { continue }
        $bytes = $nic.GetPhysicalAddress().GetAddressBytes()
        if ($bytes.Length -eq 6) { $mac = (($bytes | ForEach-Object { $_.ToString('x2') }) -join ':'); if (-not $found.Contains($mac)) { $found.Add($mac) } }
    }
    return , $found.ToArray()
}

function Get-FullName {
    $system = Get-CimInstance -ClassName Win32_ComputerSystem
    if ((Prop $system 'PartOfDomain') -and (Prop $system 'DNSHostName') -and (Prop $system 'Domain')) { return ("$($system.DNSHostName).$($system.Domain)").ToLower() }
    return ''
}

function Get-OsBlock {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $current = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $parts = ([string]$os.Version).Split('.')
    $build = '{0}.{1}.{2}' -f $parts[0], $parts[1], $os.BuildNumber
    $revision = Prop $current 'UBR'
    if ($null -ne $revision) { $build = "$build.$revision" }  # the update revision: what a monthly cumulative update moves
    $release = Prop $current 'DisplayVersion'
    if (-not $release) { $release = Prop $current 'ReleaseId' }
    $arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    $name = (Clean $os.Caption 120) -replace '^Microsoft\s+', ''
    $block = [ordered]@{
        family = 'windows'; id = 'windows'; name = $name; version = (Clean $release 60); build = $build
        edition = (Clean (Prop $current 'EditionID') 80); pretty = (Clean "$name $release (build $build)" 160)
        arch = (Clean $arch 20); last_boot = (Utc $os.LastBootUpTime)
    }
    $clean = [ordered]@{}
    foreach ($key in $block.Keys) { if ($block[$key]) { $clean[$key] = $block[$key] } }
    return $clean
}

function Get-Patches {
    $patches = @{}
    try {
        foreach ($fix in Get-HotFix) {
            if (-not $fix.HotFixID) { continue }
            $installed = if ($fix.InstalledOn) { Day $fix.InstalledOn } else { '' }
            $patches[[string]$fix.HotFixID] = @{ i = [string]$fix.HotFixID; t = $installed; d = (Clean $fix.Description 100) }
        }
    } catch { Write-Info "could not read Get-HotFix ($($_.Exception.Message))" }
    # Get-HotFix lists only what Component Based Servicing installed; the Windows Update Agent's local history knows the rest. This
    # reads the history database on this machine: it does not contact Windows Update.
    try {
        $searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
        $total = [int]$searcher.GetTotalHistoryCount()
        if ($total -gt 0) {
            $entries = @($searcher.QueryHistory(0, [Math]::Min($total, 1000)))
            [array]::Reverse($entries)  # the history comes newest first; an uninstall must undo the install before it
            foreach ($entry in $entries) {
                if ($entry.ResultCode -ne 2 -or ([string]$entry.Title) -notmatch 'KB(\d{4,8})') { continue }
                $id = 'KB' + $Matches[1]
                if ($entry.Operation -eq 1) { $patches[$id] = @{ i = $id; t = (Day $entry.Date); d = (Clean $entry.Title 100) } }
                elseif ($entry.Operation -eq 2) { $patches.Remove($id) }
            }
        }
    } catch { Write-Info "could not read the Windows Update history ($($_.Exception.Message))" }
    return , @($patches.Values | Sort-Object { $_.i })
}

function Get-Software {
    $keys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
    # the software installed for each signed-in user lives in that user's loaded registry hive
    foreach ($hive in (Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue)) {
        if ($hive.PSChildName -match '^S-1-5-21-[\d-]+$') { $keys += "Registry::HKEY_USERS\$($hive.PSChildName)\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" }
    }
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($key in $keys) {
        foreach ($entry in (Get-ItemProperty -Path $key -ErrorAction SilentlyContinue)) {
            $name = Clean (Prop $entry 'DisplayName') 200
            $version = Clean (Prop $entry 'DisplayVersion') 100
            if (-not $name -or -not $version -or (Prop $entry 'ParentKeyName') -or $name -match '^(Security Update|Update|Hotfix) for .*\(KB\d+\)') { continue }
            $item = @{ n = $name; v = $version; e = 'win' }
            if ($key -like '*WOW6432Node*') { $item['a'] = 'x86' }
            $list.Add($item)
        }
    }
    return , $list.ToArray()
}

function Get-Listening {
    $names = @{}
    foreach ($process in (Get-Process -ErrorAction SilentlyContinue)) { $names[[int]$process.Id] = $process.ProcessName }
    $rows = New-Object System.Collections.Generic.List[object]
    $add = {
        param($Proto, $Address, $Port, $ProcessId)
        $address = ([string]$Address -split '%')[0]
        if ($address -in @('0.0.0.0', '::', '')) { $address = '*' }
        $row = @{ p = $Proto; a = $address; n = [int]$Port }
        if ($names.ContainsKey([int]$ProcessId)) { $row['x'] = $names[[int]$ProcessId] }
        $rows.Add($row)
    }
    foreach ($connection in @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)) { & $add 'tcp' $connection.LocalAddress $connection.LocalPort $connection.OwningProcess }
    foreach ($endpoint in @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue)) { & $add 'udp' $endpoint.LocalAddress $endpoint.LocalPort $endpoint.OwningProcess }
    return , $rows.ToArray()
}

function Get-RebootPending {
    $cbs = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    $wu = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    $agent = $false
    try { $agent = [bool](New-Object -ComObject Microsoft.Update.SystemInfo).RebootRequired } catch { $agent = $false }
    return ($cbs -or $wu -or $agent)
}

function Get-Runtime {
    $running = @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' } | ForEach-Object { Clean $_.Name 100 })
    $features = @()
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {  # Windows Server roles and features
        $features = @(Get-WindowsFeature -ErrorAction SilentlyContinue | Where-Object { $_.Installed } | ForEach-Object { Clean $_.Name 100 })
    }
    return @{ reboot_required = (Get-RebootPending); kernels_installed = @(); containers = @(); units = $running; features = $features }
}

function Get-SecurityState {
    $state = [ordered]@{}
    try {
        $defender = Get-MpComputerStatus -ErrorAction Stop
        $state['antivirus'] = 'Microsoft Defender: ' + $(if ($defender.AntivirusEnabled) { 'on' } else { 'off' }) + ', real-time ' + $(if ($defender.RealTimeProtectionEnabled) { 'on' } else { 'off' })
        $state['antivirus_signature_age_days'] = [int]$defender.AntivirusSignatureAge
    } catch {
        try {  # client editions list every registered antivirus here
            $products = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop | ForEach-Object { Clean $_.displayName 60 })
            if ($products.Count) { $state['antivirus'] = Clean ($products -join '; ') 120 }
        } catch { Write-Verbose 'no antivirus information' }
    }
    try {
        $profiles = @(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { $_.Name + '=' + $(if ($_.Enabled) { 'on' } else { 'off' }) })
        if ($profiles.Count) { $state['firewall'] = Clean ($profiles -join ', ') 80 }
    } catch { Write-Verbose 'no firewall information' }
    try {  # needs an administrator and the BitLocker module; without them the field is left out
        $volume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
        $state['disk_encryption'] = 'BitLocker ' + $env:SystemDrive + ' ' + $(if ($volume.ProtectionStatus -eq 'On') { 'on' } else { 'off' })
    } catch { Write-Verbose 'no BitLocker information' }
    try { $state['secure_boot'] = $(if (Confirm-SecureBootUEFI) { 'enabled' } else { 'disabled' }) } catch { Write-Verbose 'no Secure Boot information' }
    $policy = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue
    if ($policy -and (Prop $policy 'NoAutoUpdate') -eq 1) { $state['auto_updates'] = 'disabled by policy' }
    return $state
}

function New-Report {
    $guid = Try-Collect 'the machine id' { (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -ErrorAction Stop).MachineGuid } ''
    $hostname = [System.Net.Dns]::GetHostName()
    $fqdn = Try-Collect 'the domain name' { Get-FullName } ''
    $hostBlock = [ordered]@{ hostname = $hostname }
    if ($fqdn) { $hostBlock['fqdn'] = $fqdn }
    if ($guid) { $hostBlock['machine_id'] = Sha256Hex ("cvengine-inventory-v1:" + $guid) }
    $hostBlock['ips'] = Try-Collect 'the addresses' { Get-Addresses } @()
    if ($IncludeMacs) { $hostBlock['macs'] = Try-Collect 'the MAC addresses' { Get-MacAddresses } @() }
    $osBlock = Get-OsBlock
    $patches = Try-Collect 'the updates' { Get-Patches } @()
    $latest = @($patches | ForEach-Object { $_.t } | Where-Object { $_ } | Sort-Object | Select-Object -Last 1)
    if ($latest.Count -and $latest[0]) { $osBlock['last_update'] = $latest[0] + 'T00:00:00Z' }
    return [ordered]@{
        schema = 'cvengine-inventory/1'
        script = @{ name = $ScriptName; version = $ScriptVersion }
        collected_at = (Utc (Get-Date))
        host = $hostBlock
        os = $osBlock
        packages = (Try-Collect 'the installed software' { Get-Software } @())
        patches = $patches
        services = (Try-Collect 'the listening ports' { Get-Listening } @())
        runtime = (Try-Collect 'the runtime state' { Get-Runtime } @{})
        security = (Try-Collect 'the security settings' { Get-SecurityState } @{})
    }
}

# --- sending ---------------------------------------------------------------------------------------------------------------

# Server certificate checking for HttpWebRequest. Windows PowerShell 5.1 and PowerShell 7 both honour this per-request callback, which
# a script block would not do safely on a network thread, so it is compiled C#. With -CaFile a certificate that chains to that one
# authority is accepted (the host name must still match); with -Insecure anything is.
$TrustSource = @'
using System;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

public class CvEngineTrust
{
    private readonly X509Certificate2 authority;
    private readonly bool anything;

    public CvEngineTrust(X509Certificate2 authority, bool anything)
    {
        this.authority = authority;
        this.anything = anything;
    }

    public RemoteCertificateValidationCallback GetCallback()
    {
        return new RemoteCertificateValidationCallback(this.Validate);
    }

    private bool Validate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
    {
        if (anything) { return true; }
        if (errors == SslPolicyErrors.None) { return true; }
        if (authority == null) { return false; }
        if ((errors & ~SslPolicyErrors.RemoteCertificateChainErrors) != SslPolicyErrors.None) { return false; }
        X509Chain own = new X509Chain();
        own.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        own.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
        own.ChainPolicy.ExtraStore.Add(authority);
        if (!own.Build(new X509Certificate2(certificate))) { return false; }
        X509Certificate2 root = own.ChainElements[own.ChainElements.Count - 1].Certificate;
        return root.Thumbprint == authority.Thumbprint;
    }
}
'@

function Read-Authority([string]$Path) {
    $pem = [System.IO.File]::ReadAllText($Path)
    if ($pem -notmatch '-----BEGIN CERTIFICATE-----([^-]+)-----END CERTIFICATE-----') { throw [Failure]::new(1, "$Path holds no PEM certificate") }
    return New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (, [Convert]::FromBase64String(($Matches[1] -replace '\s', '')))
}

function Read-Response($Response) {
    if ($null -eq $Response) { return '' }
    $reader = New-Object System.IO.StreamReader($Response.GetResponseStream())
    try { $text = $reader.ReadToEnd() } finally { $reader.Dispose(); $Response.Close() }
    return (Clean $text 300)
}

function Send-Report([string]$Url, [string]$Token, [byte[]]$Body, $Callback) {
    $attempt = 0
    while ($true) {
        $why = ''
        $code = 3
        try {
            $request = [System.Net.HttpWebRequest]::Create($Url)
            $request.Method = 'POST'
            $request.ContentType = 'application/json'
            $request.UserAgent = "$ScriptName/$ScriptVersion"
            $request.Headers.Add('Authorization', "Bearer $Token")
            $request.Timeout = $TimeoutSec * 1000
            $request.ReadWriteTimeout = $TimeoutSec * 1000
            $request.AllowAutoRedirect = $false  # the token only ever goes to the address given
            $request.ContentLength = $Body.Length
            $request.ServerCertificateValidationCallback = $Callback
            $stream = $request.GetRequestStream()
            try { $stream.Write($Body, 0, $Body.Length) } finally { $stream.Dispose() }
            $response = $request.GetResponse()
            Write-Info ("sent: " + (Read-Response $response))
            return 0
        } catch [System.Net.WebException] {
            $failure = $_.Exception
            if ($null -ne $failure.Response) {
                $status = [int]$failure.Response.StatusCode
                $text = Read-Response $failure.Response
                if (($status -in 408, 429) -or ($status -ge 500)) { $why = "the server answered $status"; $code = 5 }
                else { Write-Info "the server refused the report ($status): $text"; return 4 }
            } elseif (([string]$failure.Status -in 'TrustFailure', 'SecureChannelFailure') -or ($failure.Message -match 'certificate|SSL|TLS')) {
                Write-Info "the server's certificate is not trusted ($($failure.Message)). For a private certificate authority pass -CaFile (the installer's secrets\certs\ca.crt)."
                return 3
            } else { $why = "could not reach the server: $($failure.Message)" }
        } catch { $why = "could not reach the server: $($_.Exception.Message)" }
        $attempt++
        if ($attempt -gt $Retries) { Write-Info "giving up after $attempt attempts: $why"; return $code }
        $delay = [Math]::Pow(2, $attempt) + (Get-Random -Minimum 0 -Maximum 4)  # growing, with spread so a fleet does not retry together
        Write-Info "$why; retrying in ${delay}s ($attempt of $Retries)"
        Start-Sleep -Seconds $delay
    }
}

function Get-Token {
    $token = $env:CVENGINE_TOKEN
    if ($TokenFile) {
        if (-not (Test-Path -LiteralPath $TokenFile)) { throw [Failure]::new(1, "cannot read the token file $TokenFile") }
        try {
            $open = @((Get-Acl -LiteralPath $TokenFile).Access | Where-Object { $_.IdentityReference.Value -match '^(BUILTIN\\Users|Everyone|NT AUTHORITY\\Authenticated Users)$' })
            if ($open.Count) { Write-Info "warning: $TokenFile is readable by ordinary users: restrict it to SYSTEM and Administrators" }
        } catch { Write-Verbose 'could not check the token file permissions' }
        $token = ([System.IO.File]::ReadAllLines($TokenFile) | Select-Object -First 1)
    }
    if ($token) { $token = $token.Trim() }
    if ($token -notmatch '^cve_[A-Za-z0-9_-]{20,200}\z') { throw [Failure]::new(1, 'no usable token: set CVENGINE_TOKEN or -TokenFile (a cvENGINE inventory token, cve_...)') }
    return $token
}

function Main {
    if ($Version) { [Console]::Out.WriteLine("$ScriptName $ScriptVersion"); return 0 }
    if ($Schedule) {
        # these go into a command a person pastes into an elevated shell: check them first
        if ($Server -and $Server -notmatch '^https://[A-Za-z0-9._:\[\]-]+(/[A-Za-z0-9._~/-]*)?\z') { throw [Failure]::new(1, '-Server must be a plain https:// address') }
        if ($Project -and $Project -notmatch '^[-A-Za-z0-9_]+\z') { throw [Failure]::new(1, '-Project is letters, digits, - and _') }
        [Console]::Out.WriteLine((Show-Schedule))
        return 0
    }
    if ($env:OS -ne 'Windows_NT') { throw [Failure]::new(2, 'this script collects from Windows; use cvengine-inventory.sh or .py on Linux and macOS') }
    $token = $null
    $callback = $null
    if (-not $DryRun) {
        if ($Server -notmatch '^https://[A-Za-z0-9._:\[\]-]+(/[A-Za-z0-9._~/-]*)?\z') { throw [Failure]::new(1, '-Server must be a plain https:// address (or set CVENGINE_URL): the token never travels in the clear') }
        if ($Project -notmatch '^[-A-Za-z0-9_]+\z') { throw [Failure]::new(1, '-Project (the project slug) is required') }
        $token = Get-Token
        $authority = $null
        if ($CaFile) { $authority = Read-Authority $CaFile }
        if ($Insecure) { Write-Warning "*** -Insecure: the server's certificate is NOT being checked. Anyone on the network path can read the token and this report. ***" }
        try { Add-Type -TypeDefinition $TrustSource -Language CSharp -ErrorAction Stop } catch { if (-not ([System.Management.Automation.PSTypeName]'CvEngineTrust').Type) { throw } }
        $callback = (New-Object CvEngineTrust -ArgumentList $authority, ([bool]$Insecure)).GetCallback()
        try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { Write-Verbose 'TLS 1.2 is already the default' }
    }
    $report = New-Report
    $json = ConvertTo-Json -InputObject $report -Depth 8 -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    Write-Info ("collected {0} software entries ({1} bytes) on {2}" -f @($report.packages).Count, $bytes.Length, $report.host.hostname)
    if ($DryRun) {
        [Console]::Out.WriteLine($json)
        Write-Info "dry run: nothing was sent. It would POST to $(if ($Server) { $Server } else { '<-Server>' })/api/v1/projects/$(if ($Project) { $Project } else { '<-Project>' })/inventory"
        return 0
    }
    return (Send-Report ($Server.TrimEnd('/') + "/api/v1/projects/$Project/inventory") $token $bytes $callback)
}

try { $exitCode = [int](@(Main)[-1]) } catch [Failure] { Write-Info $_.Exception.Message; $exitCode = $_.Exception.Code } catch { Write-Info $_.Exception.Message; $exitCode = 2 }
exit $exitCode
