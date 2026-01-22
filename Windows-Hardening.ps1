#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CyberPatriot Windows Server Hardening Script
.DESCRIPTION
    Comprehensive hardening script for Windows Server (2019/2022)
    Covers users, policies, services, firewall, and more
.NOTES
    Run as Administrator
    Review README before running - update $AuthorizedUsers and $AuthorizedAdmins
#>

# ============================================================
# CONFIGURATION - UPDATE THESE FROM YOUR README
# ============================================================

$AuthorizedUsers = @(
    "Administrator",
    "User1",
    "User2"
    # Add all authorized users from README here
)

$AuthorizedAdmins = @(
    "Administrator"
    # Add all authorized administrators from README here
)

$RequiredServices = @(
    # Add services that must remain running per README
    # Example: "W3SVC" for IIS if web server is required
)

# ============================================================
# LOGGING SETUP
# ============================================================

$LogFile = "C:\CyberPatriot-Hardening-Log-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"

function Write-Log {
    param([string]$Message, [string]$Color = "White")
    $timestamp = Get-Date -Format "HH:mm:ss"
    $logMessage = "[$timestamp] $Message"
    Write-Host $logMessage -ForegroundColor $Color
    Add-Content -Path $LogFile -Value $logMessage
}

function Write-Success { param([string]$Message) Write-Log "[+] $Message" "Green" }
function Write-Warning { param([string]$Message) Write-Log "[!] $Message" "Yellow" }
function Write-Alert { param([string]$Message) Write-Log "[!!!] $Message" "Red" }
function Write-Info { param([string]$Message) Write-Log "[*] $Message" "Cyan" }

# ============================================================
# USER MANAGEMENT
# ============================================================

function Invoke-UserAudit {
    Write-Info "========== USER AUDIT =========="
    
    # Get all local users
    $allUsers = Get-LocalUser
    
    foreach ($user in $allUsers) {
        if ($user.Name -notin $AuthorizedUsers) {
            Write-Alert "Unauthorized user found: $($user.Name)"
            Write-Host "    Disable? (y/n): " -NoNewline -ForegroundColor Yellow
            $response = Read-Host
            if ($response -eq 'y') {
                Disable-LocalUser -Name $user.Name
                Write-Success "Disabled user: $($user.Name)"
            }
        } else {
            Write-Success "Authorized user: $($user.Name)"
        }
    }
    
    # Check Guest account
    $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if ($guest -and $guest.Enabled) {
        Disable-LocalUser -Name "Guest"
        Write-Success "Disabled Guest account"
    }
}

function Invoke-AdminAudit {
    Write-Info "========== ADMIN GROUP AUDIT =========="
    
    $adminGroup = Get-LocalGroupMember -Group "Administrators"
    
    foreach ($member in $adminGroup) {
        $username = $member.Name.Split('\')[-1]
        if ($username -notin $AuthorizedAdmins) {
            Write-Alert "Unauthorized admin: $($member.Name)"
            Write-Host "    Remove from Administrators? (y/n): " -NoNewline -ForegroundColor Yellow
            $response = Read-Host
            if ($response -eq 'y') {
                Remove-LocalGroupMember -Group "Administrators" -Member $member.Name -ErrorAction SilentlyContinue
                Write-Success "Removed $($member.Name) from Administrators"
            }
        } else {
            Write-Success "Authorized admin: $($member.Name)"
        }
    }
}

function Set-SecurePasswords {
    Write-Info "========== PASSWORD ENFORCEMENT =========="
    
    # Force password change for all users (optional)
    Write-Host "Force all users to change password at next logon? (y/n): " -NoNewline -ForegroundColor Yellow
    $response = Read-Host
    if ($response -eq 'y') {
        foreach ($user in $AuthorizedUsers) {
            if ($user -ne "Administrator") {
                $userObj = Get-LocalUser -Name $user -ErrorAction SilentlyContinue
                if ($userObj) {
                    Set-LocalUser -Name $user -PasswordNeverExpires $false
                    # Force password change
                    net user $user /logonpasswordchg:yes 2>$null
                    Write-Success "Password change required for: $user"
                }
            }
        }
    }
}

# ============================================================
# PASSWORD POLICY
# ============================================================

function Set-PasswordPolicy {
    Write-Info "========== PASSWORD POLICY =========="
    
    # Using net accounts for local policy
    net accounts /minpwlen:12 /maxpwage:30 /minpwage:1 /uniquepw:5 /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30
    
    Write-Success "Password policy configured:"
    Write-Success "  - Minimum length: 12"
    Write-Success "  - Maximum age: 30 days"
    Write-Success "  - Minimum age: 1 day"
    Write-Success "  - History: 5 passwords"
    Write-Success "  - Lockout threshold: 5 attempts"
    Write-Success "  - Lockout duration: 30 minutes"
    
    # Export current security policy, modify, and import
    $secEditPath = "$env:TEMP\secpol.cfg"
    secedit /export /cfg $secEditPath /quiet
    
    # Modify password complexity
    (Get-Content $secEditPath) -replace 'PasswordComplexity = 0', 'PasswordComplexity = 1' | Set-Content $secEditPath
    
    # Import modified policy
    secedit /configure /db secedit.sdb /cfg $secEditPath /quiet
    Remove-Item $secEditPath -ErrorAction SilentlyContinue
    
    Write-Success "Password complexity enabled"
}

# ============================================================
# AUDIT POLICY
# ============================================================

function Set-AuditPolicy {
    Write-Info "========== AUDIT POLICY =========="
    
    # Enable comprehensive auditing
    $auditCategories = @(
        "Account Logon",
        "Account Management",
        "Logon/Logoff",
        "Object Access",
        "Policy Change",
        "Privilege Use",
        "System",
        "DS Access"
    )
    
    foreach ($category in $auditCategories) {
        auditpol /set /category:"$category" /success:enable /failure:enable 2>$null
        Write-Success "Enabled auditing: $category"
    }
}

# ============================================================
# LOCAL SECURITY POLICY
# ============================================================

function Set-SecurityOptions {
    Write-Info "========== SECURITY OPTIONS =========="
    
    # These require registry modifications
    $regSettings = @(
        # Don't display last username
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="DontDisplayLastUserName"; Value=1},
        
        # UAC settings
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableLUA"; Value=1},
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="ConsentPromptBehaviorAdmin"; Value=2},
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="ConsentPromptBehaviorUser"; Value=0},
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="PromptOnSecureDesktop"; Value=1},
        
        # Machine inactivity limit (900 seconds = 15 min)
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="InactivityTimeoutSecs"; Value=900},
        
        # Disable anonymous enumeration
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RestrictAnonymous"; Value=1},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RestrictAnonymousSAM"; Value=1},
        
        # LAN Manager authentication level (NTLMv2 only)
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="LmCompatibilityLevel"; Value=5},
        
        # SMB signing
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="RequireSecuritySignature"; Value=1},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="RequireSecuritySignature"; Value=1},
        
        # Disable autorun
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoAutorun"; Value=1},
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoDriveTypeAutoRun"; Value=255},
        
        # Disable remote assistance
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"; Name="fAllowToGetHelp"; Value=0},
        
        # Disable admin shares
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="AutoShareWks"; Value=0},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="AutoShareServer"; Value=0}
    )
    
    foreach ($setting in $regSettings) {
        if (!(Test-Path $setting.Path)) {
            New-Item -Path $setting.Path -Force | Out-Null
        }
        Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type DWord -ErrorAction SilentlyContinue
        Write-Success "Set: $($setting.Name) = $($setting.Value)"
    }
}

function Set-UserRightsAssignment {
    Write-Info "========== USER RIGHTS ASSIGNMENT =========="
    
    # This requires secedit
    # Export, modify, and reimport security policy
    
    Write-Warning "User Rights Assignment requires manual review in secpol.msc"
    Write-Warning "Check these settings:"
    Write-Warning "  - 'Access this computer from network' - Remove unnecessary users"
    Write-Warning "  - 'Deny log on locally' - Add Guest"
    Write-Warning "  - 'Debug programs' - Administrators only or empty"
    Write-Warning "  - 'Act as part of OS' - Should be empty"
}

# ============================================================
# SERVICES
# ============================================================

function Invoke-ServiceAudit {
    Write-Info "========== SERVICE AUDIT =========="
    
    # Dangerous services to disable
    $dangerousServices = @(
        "RemoteRegistry",      # Remote Registry
        "TermService",         # Remote Desktop (disable if not needed)
        "Telnet",              # Telnet
        "tlntsvr",             # Telnet Server
        "SNMP",                # SNMP
        "SNMPTRAP",            # SNMP Trap
        "SSDPSRV",             # SSDP Discovery
        "upnphost",            # UPnP Device Host
        "WinRM",               # Windows Remote Management (if not needed)
        "RpcLocator",          # RPC Locator
        "RemoteAccess",        # Routing and Remote Access
        "Browser",             # Computer Browser
        "FTPSVC",              # FTP
        "W3SVC",               # IIS (if not needed)
        "XboxGipSvc",          # Xbox Accessory Management
        "XblAuthManager",      # Xbox Live Auth Manager
        "XblGameSave",         # Xbox Live Game Save
        "XboxNetApiSvc"        # Xbox Live Networking Service
    )
    
    foreach ($svcName in $dangerousServices) {
        # Skip if it's a required service
        if ($svcName -in $RequiredServices) {
            Write-Info "Skipping required service: $svcName"
            continue
        }
        
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc) {
            if ($svc.Status -eq "Running") {
                Write-Alert "Dangerous service running: $svcName"
            }
            Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
            Set-Service -Name $svcName -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Success "Disabled service: $svcName"
        }
    }
    
    # Ensure critical services are running
    $criticalServices = @(
        "wuauserv",            # Windows Update
        "WinDefend",           # Windows Defender
        "MpsSvc",              # Windows Firewall
        "EventLog",            # Windows Event Log
        "Dnscache"             # DNS Client
    )
    
    foreach ($svcName in $criticalServices) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc) {
            if ($svc.Status -ne "Running") {
                Start-Service -Name $svcName -ErrorAction SilentlyContinue
            }
            Set-Service -Name $svcName -StartupType Automatic -ErrorAction SilentlyContinue
            Write-Success "Enabled critical service: $svcName"
        }
    }
}

# ============================================================
# FIREWALL
# ============================================================

function Set-FirewallConfiguration {
    Write-Info "========== FIREWALL CONFIGURATION =========="
    
    # Enable firewall on all profiles
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    Write-Success "Firewall enabled on all profiles"
    
    # Set default actions
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow
    Write-Success "Default inbound: Block, Default outbound: Allow"
    
    # Enable logging
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogBlocked True -LogAllowed False
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log"
    Write-Success "Firewall logging enabled"
    
    # Review and disable suspicious inbound rules
    Write-Info "Reviewing inbound rules..."
    $suspiciousRules = Get-NetFirewallRule -Direction Inbound -Enabled True | Where-Object {
        $_.DisplayName -match "game|torrent|remote|vnc|teamviewer|anydesk" -or
        $_.DisplayName -match "ftp|telnet|tftp"
    }
    
    foreach ($rule in $suspiciousRules) {
        Write-Alert "Suspicious firewall rule: $($rule.DisplayName)"
        Write-Host "    Disable? (y/n): " -NoNewline -ForegroundColor Yellow
        $response = Read-Host
        if ($response -eq 'y') {
            Disable-NetFirewallRule -Name $rule.Name
            Write-Success "Disabled rule: $($rule.DisplayName)"
        }
    }
}

# ============================================================
# WINDOWS DEFENDER
# ============================================================

function Set-DefenderConfiguration {
    Write-Info "========== WINDOWS DEFENDER =========="
    
    # Enable real-time protection
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
    Write-Success "Real-time protection enabled"
    
    # Enable cloud protection
    Set-MpPreference -MAPSReporting Advanced -ErrorAction SilentlyContinue
    Set-MpPreference -SubmitSamplesConsent SendAllSamples -ErrorAction SilentlyContinue
    Write-Success "Cloud protection enabled"
    
    # Enable PUA protection
    Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue
    Write-Success "PUA protection enabled"
    
    # Check for exclusions (attackers add malware paths here)
    $exclusions = Get-MpPreference
    if ($exclusions.ExclusionPath) {
        Write-Alert "Defender exclusion paths found:"
        foreach ($path in $exclusions.ExclusionPath) {
            Write-Alert "  - $path"
        }
        Write-Host "Remove all exclusions? (y/n): " -NoNewline -ForegroundColor Yellow
        $response = Read-Host
        if ($response -eq 'y') {
            foreach ($path in $exclusions.ExclusionPath) {
                Remove-MpPreference -ExclusionPath $path
            }
            Write-Success "Removed all exclusion paths"
        }
    }
    
    # Update definitions
    Write-Info "Updating Defender definitions..."
    Update-MpSignature -ErrorAction SilentlyContinue
    
    # Quick scan
    Write-Host "Run quick scan? (y/n): " -NoNewline -ForegroundColor Yellow
    $response = Read-Host
    if ($response -eq 'y') {
        Start-MpScan -ScanType QuickScan -AsJob
        Write-Info "Quick scan started in background"
    }
}

# ============================================================
# WINDOWS UPDATE
# ============================================================

function Set-WindowsUpdate {
    Write-Info "========== WINDOWS UPDATE =========="
    
    # Enable Windows Update service
    Set-Service -Name wuauserv -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name wuauserv -ErrorAction SilentlyContinue
    
    # Configure automatic updates via registry
    $WUPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    if (!(Test-Path $WUPath)) {
        New-Item -Path $WUPath -Force | Out-Null
    }
    
    Set-ItemProperty -Path $WUPath -Name "NoAutoUpdate" -Value 0 -Type DWord
    Set-ItemProperty -Path $WUPath -Name "AUOptions" -Value 4 -Type DWord  # Auto download and install
    Set-ItemProperty -Path $WUPath -Name "ScheduledInstallDay" -Value 0 -Type DWord  # Every day
    Set-ItemProperty -Path $WUPath -Name "ScheduledInstallTime" -Value 3 -Type DWord  # 3 AM
    
    Write-Success "Windows Update configured for automatic updates"
    
    # Check for updates
    Write-Host "Check for updates now? (y/n): " -NoNewline -ForegroundColor Yellow
    $response = Read-Host
    if ($response -eq 'y') {
        Write-Info "Checking for updates... (this may take a while)"
        $UpdateSession = New-Object -ComObject Microsoft.Update.Session
        $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
        $SearchResult = $UpdateSearcher.Search("IsInstalled=0")
        Write-Info "Found $($SearchResult.Updates.Count) updates available"
    }
}

# ============================================================
# PROHIBITED SOFTWARE
# ============================================================

function Find-ProhibitedSoftware {
    Write-Info "========== PROHIBITED SOFTWARE SCAN =========="
    
    # Patterns for prohibited software
    $prohibitedPatterns = @(
        "*wireshark*",
        "*nmap*",
        "*cain*",
        "*abel*",
        "*keylogger*",
        "*metasploit*",
        "*john*",          # John the Ripper
        "*hashcat*",
        "*aircrack*",
        "*burp*",
        "*netcat*",
        "*nc.exe*",
        "*utorrent*",
        "*bittorrent*",
        "*vuze*",
        "*limewire*",
        "*kazaa*",
        "*emule*",
        "*frostwire*",
        "*steam*",
        "*origin*",
        "*epicgames*",
        "*minecraft*",
        "*fortnite*",
        "*league of legends*",
        "*teamviewer*",
        "*anydesk*",
        "*logmein*",
        "*vnc*",
        "*putty*"          # Might be legitimate - review
    )
    
    # Check installed programs
    $installedApps = @()
    $installedApps += Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue
    $installedApps += Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue
    $installedApps += Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue
    
    foreach ($pattern in $prohibitedPatterns) {
        $found = $installedApps | Where-Object { $_.DisplayName -like $pattern }
        foreach ($app in $found) {
            Write-Alert "Prohibited software: $($app.DisplayName)"
            Write-Warning "  Location: $($app.InstallLocation)"
            Write-Warning "  Uninstall: $($app.UninstallString)"
        }
    }
    
    # Scan common directories for suspicious executables
    Write-Info "Scanning for suspicious files..."
    
    $scanPaths = @(
        "C:\Users\*\Desktop",
        "C:\Users\*\Downloads",
        "C:\Users\*\Documents",
        "C:\Temp",
        "C:\Windows\Temp"
    )
    
    $suspiciousExtensions = @("*.exe", "*.bat", "*.cmd", "*.ps1", "*.vbs", "*.msi")
    
    foreach ($scanPath in $scanPaths) {
        foreach ($ext in $suspiciousExtensions) {
            $files = Get-ChildItem -Path $scanPath -Filter $ext -Recurse -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                Write-Warning "Suspicious file: $($file.FullName)"
            }
        }
    }
}

# ============================================================
# SHARES
# ============================================================

function Invoke-ShareAudit {
    Write-Info "========== SHARE AUDIT =========="
    
    $shares = Get-SmbShare | Where-Object { $_.Name -notmatch '^\$' }  # Exclude admin shares
    
    foreach ($share in $shares) {
        Write-Warning "Share found: $($share.Name) -> $($share.Path)"
        $perms = Get-SmbShareAccess -Name $share.Name
        foreach ($perm in $perms) {
            Write-Warning "  $($perm.AccountName): $($perm.AccessRight)"
        }
        
        Write-Host "    Remove this share? (y/n): " -NoNewline -ForegroundColor Yellow
        $response = Read-Host
        if ($response -eq 'y') {
            Remove-SmbShare -Name $share.Name -Force
            Write-Success "Removed share: $($share.Name)"
        }
    }
}

# ============================================================
# SCHEDULED TASKS
# ============================================================

function Invoke-ScheduledTaskAudit {
    Write-Info "========== SCHEDULED TASK AUDIT =========="
    
    # Get non-Microsoft scheduled tasks
    $tasks = Get-ScheduledTask | Where-Object { 
        $_.TaskPath -notmatch "Microsoft" -and 
        $_.State -ne "Disabled" 
    }
    
    foreach ($task in $tasks) {
        $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
        Write-Warning "Task: $($task.TaskPath)$($task.TaskName)"
        Write-Warning "  State: $($task.State)"
        
        $actions = $task.Actions
        foreach ($action in $actions) {
            Write-Warning "  Action: $($action.Execute) $($action.Arguments)"
        }
        
        Write-Host "    Disable this task? (y/n): " -NoNewline -ForegroundColor Yellow
        $response = Read-Host
        if ($response -eq 'y') {
            Disable-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath
            Write-Success "Disabled task: $($task.TaskName)"
        }
    }
}

# ============================================================
# FEATURES AND ROLES (Server-specific)
# ============================================================

function Invoke-FeatureAudit {
    Write-Info "========== FEATURES AND ROLES AUDIT =========="
    
    # Dangerous features to check
    $dangerousFeatures = @(
        "Telnet-Client",
        "Telnet-Server",
        "TFTP-Client",
        "SMB1Protocol",
        "SMB1Protocol-Client",
        "SMB1Protocol-Server",
        "PowerShell-V2"      # Legacy PowerShell
    )
    
    foreach ($feature in $dangerousFeatures) {
        $installed = Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction SilentlyContinue
        if ($installed -and $installed.State -eq "Enabled") {
            Write-Alert "Dangerous feature enabled: $feature"
            Write-Host "    Disable? (y/n): " -NoNewline -ForegroundColor Yellow
            $response = Read-Host
            if ($response -eq 'y') {
                Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart
                Write-Success "Disabled feature: $feature"
            }
        }
    }
    
    # List installed roles (Server)
    Write-Info "Installed Server Roles:"
    Get-WindowsFeature | Where-Object { $_.Installed -eq $true -and $_.FeatureType -eq "Role" } | ForEach-Object {
        Write-Info "  - $($_.DisplayName)"
    }
}

# ============================================================
# QUICK WINS
# ============================================================

function Invoke-QuickWins {
    Write-Info "========== QUICK WINS =========="
    
    # Rename Administrator account
    Write-Host "Rename Administrator account? (y/n): " -NoNewline -ForegroundColor Yellow
    $response = Read-Host
    if ($response -eq 'y') {
        Write-Host "    New name: " -NoNewline
        $newName = Read-Host
        Rename-LocalUser -Name "Administrator" -NewName $newName -ErrorAction SilentlyContinue
        Write-Success "Renamed Administrator to $newName"
    }
    
    # Rename Guest account
    Rename-LocalUser -Name "Guest" -NewName "NoGuest" -ErrorAction SilentlyContinue
    Write-Success "Renamed Guest account"
    
    # Clear DNS cache
    Clear-DnsClientCache
    Write-Success "Cleared DNS cache"
    
    # Enable DEP (Data Execution Prevention)
    bcdedit /set nx AlwaysOn 2>$null
    Write-Success "DEP set to AlwaysOn"
    
    # Disable IPv6 if not needed
    Write-Host "Disable IPv6? (y/n): " -NoNewline -ForegroundColor Yellow
    $response = Read-Host
    if ($response -eq 'y') {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Value 255 -Type DWord
        Write-Success "IPv6 disabled (requires restart)"
    }
}

# ============================================================
# FORENSICS HELPER
# ============================================================

function Get-ForensicsInfo {
    Write-Info "========== FORENSICS HELPER =========="
    
    Write-Info "Last 10 Security Events (Logon Failures):"
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 10 -ErrorAction SilentlyContinue | 
        Format-Table TimeCreated, Message -AutoSize -Wrap
    
    Write-Info "Last 10 Installed Programs:"
    Get-WinEvent -FilterHashtable @{LogName='Application';Id=11707} -MaxEvents 10 -ErrorAction SilentlyContinue |
        Format-Table TimeCreated, Message -AutoSize -Wrap
    
    Write-Info "Last 10 User Creations:"
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4720} -MaxEvents 10 -ErrorAction SilentlyContinue |
        Format-Table TimeCreated, Message -AutoSize -Wrap
    
    Write-Info "Listening Ports:"
    Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess | Sort-Object LocalPort
    
    Write-Info "Running Processes (unusual):"
    Get-Process | Where-Object { $_.Path -and $_.Path -notmatch "Windows|Program Files" } |
        Select-Object Name, Path, Id | Format-Table -AutoSize
}

# ============================================================
# MAIN MENU
# ============================================================

function Show-Menu {
    Clear-Host
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "  CYBERPATRIOT WINDOWS HARDENING SCRIPT" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1]  Run ALL Hardening (Recommended)" -ForegroundColor Green
    Write-Host ""
    Write-Host "  [2]  User Audit" -ForegroundColor Yellow
    Write-Host "  [3]  Admin Group Audit" -ForegroundColor Yellow
    Write-Host "  [4]  Password Policy" -ForegroundColor Yellow
    Write-Host "  [5]  Audit Policy" -ForegroundColor Yellow
    Write-Host "  [6]  Security Options (Registry)" -ForegroundColor Yellow
    Write-Host "  [7]  Service Audit" -ForegroundColor Yellow
    Write-Host "  [8]  Firewall Configuration" -ForegroundColor Yellow
    Write-Host "  [9]  Windows Defender" -ForegroundColor Yellow
    Write-Host "  [10] Windows Update" -ForegroundColor Yellow
    Write-Host "  [11] Prohibited Software Scan" -ForegroundColor Yellow
    Write-Host "  [12] Share Audit" -ForegroundColor Yellow
    Write-Host "  [13] Scheduled Task Audit" -ForegroundColor Yellow
    Write-Host "  [14] Features/Roles Audit" -ForegroundColor Yellow
    Write-Host "  [15] Quick Wins" -ForegroundColor Yellow
    Write-Host "  [16] Forensics Helper" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  [0]  Exit" -ForegroundColor Red
    Write-Host ""
}

function Invoke-AllHardening {
    Write-Info "Running complete hardening sequence..."
    
    Invoke-UserAudit
    Invoke-AdminAudit
    Set-PasswordPolicy
    Set-AuditPolicy
    Set-SecurityOptions
    Invoke-ServiceAudit
    Set-FirewallConfiguration
    Set-DefenderConfiguration
    Set-WindowsUpdate
    Find-ProhibitedSoftware
    Invoke-ShareAudit
    Invoke-ScheduledTaskAudit
    Invoke-FeatureAudit
    Invoke-QuickWins
    
    Write-Info "=========================================="
    Write-Info "HARDENING COMPLETE"
    Write-Info "Log saved to: $LogFile"
    Write-Info "=========================================="
}

# ============================================================
# MAIN EXECUTION
# ============================================================

do {
    Show-Menu
    $choice = Read-Host "Select option"
    
    switch ($choice) {
        "1"  { Invoke-AllHardening }
        "2"  { Invoke-UserAudit }
        "3"  { Invoke-AdminAudit }
        "4"  { Set-PasswordPolicy }
        "5"  { Set-AuditPolicy }
        "6"  { Set-SecurityOptions }
        "7"  { Invoke-ServiceAudit }
        "8"  { Set-FirewallConfiguration }
        "9"  { Set-DefenderConfiguration }
        "10" { Set-WindowsUpdate }
        "11" { Find-ProhibitedSoftware }
        "12" { Invoke-ShareAudit }
        "13" { Invoke-ScheduledTaskAudit }
        "14" { Invoke-FeatureAudit }
        "15" { Invoke-QuickWins }
        "16" { Get-ForensicsInfo }
        "0"  { Write-Host "Exiting..."; break }
        default { Write-Host "Invalid option" -ForegroundColor Red }
    }
    
    if ($choice -ne "0") {
        Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
        Read-Host
    }
} while ($choice -ne "0")
