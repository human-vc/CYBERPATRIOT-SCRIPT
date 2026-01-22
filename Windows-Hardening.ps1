#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CyberPatriot Windows Server Hardening Script - Complete Edition
.DESCRIPTION
    Comprehensive hardening script for Windows Server (2019/2022) and Windows 10/11
    Covers users, policies, services, firewall, startup, hosts file, and more
.NOTES
    Run as Administrator
    Review README before running - update $AuthorizedUsers and $AuthorizedAdmins
.VERSION
    2.1 - Complete Edition with CyberPatriot Additions
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
    # Example: "TermService" if Remote Desktop is required
)

$RequiredPrograms = @(
    # Add programs that should NOT be flagged as prohibited
    # Example: "putty" if SSH client is needed
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
    
    # Check for hidden/suspicious users
    Write-Info "Checking for hidden/suspicious users..."
    $suspiciousUsers = Get-LocalUser | Where-Object {
        $_.Name -match '\$$' -or           # Ends with $
        $_.Name -match '^\.' -or           # Starts with .
        $_.Name -match 'admin' -and $_.Name -ne 'Administrator' -or
        $_.Name -match 'test|temp|backup|service'
    }
    
    foreach ($user in $suspiciousUsers) {
        if ($user.Name -notin $AuthorizedUsers) {
            Write-Alert "Suspicious user found: $($user.Name) (Enabled: $($user.Enabled))"
        }
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
    
    # Check other privileged groups
    $privilegedGroups = @("Remote Desktop Users", "Backup Operators", "Power Users", "Network Configuration Operators")
    
    foreach ($groupName in $privilegedGroups) {
        $members = Get-LocalGroupMember -Group $groupName -ErrorAction SilentlyContinue
        if ($members) {
            Write-Warning "Members of '$groupName':"
            foreach ($member in $members) {
                Write-Warning "  - $($member.Name)"
            }
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
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="FilterAdministratorToken"; Value=1},
        
        # Machine inactivity limit (900 seconds = 15 min)
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="InactivityTimeoutSecs"; Value=900},
        
        # Disable anonymous enumeration
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RestrictAnonymous"; Value=1},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RestrictAnonymousSAM"; Value=1},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="EveryoneIncludesAnonymous"; Value=0},
        
        # LAN Manager authentication level (NTLMv2 only)
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="LmCompatibilityLevel"; Value=5},
        
        # Do not store LAN Manager hash
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="NoLMHash"; Value=1},
        
        # SMB signing
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="RequireSecuritySignature"; Value=1},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="RequireSecuritySignature"; Value=1},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="EnableSecuritySignature"; Value=1},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="EnableSecuritySignature"; Value=1},
        
        # Disable autorun/autoplay
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoAutorun"; Value=1},
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoDriveTypeAutoRun"; Value=255},
        @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoDriveTypeAutoRun"; Value=255},
        
        # Disable remote assistance
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"; Name="fAllowToGetHelp"; Value=0},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"; Name="fAllowFullControl"; Value=0},
        
        # Disable admin shares
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="AutoShareWks"; Value=0},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="AutoShareServer"; Value=0},
        
        # Limit cached logons (credential caching)
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Name="CachedLogonsCount"; Value=0},
        
        # Disable LLMNR
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"; Name="EnableMulticast"; Value=0},
        
        # Disable NetBIOS over TCP/IP (may need manual per adapter)
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"; Name="NodeType"; Value=2},
        
        # Disable WPAD
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad"; Name="WpadOverride"; Value=1},
        
        # Disable WDigest (clear-text passwords in memory)
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"; Name="UseLogonCredential"; Value=0},
        
        # Enable LSA Protection
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RunAsPPL"; Value=1},
        
        # Safe DLL search mode
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"; Name="SafeDllSearchMode"; Value=1},
        
        # Prevent driver installation from removable media
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverInstall\Restrictions"; Name="AllowRemoteRPC"; Value=0},
        
        # ===== ADDITIONAL CYBERPATRIOT ITEMS =====
        
        # Require Ctrl+Alt+Del for logon
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="DisableCAD"; Value=0},
        
        # Windows SmartScreen
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name="EnableSmartScreen"; Value=1},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name="ShellSmartScreenLevel"; Value="Block"},
        
        # Legal notice banner
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="LegalNoticeCaption"; Value="Authorized Users Only"},
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="LegalNoticeText"; Value="Unauthorized access is prohibited."},
        
        # UPnP disable
        @{Path="HKLM:\SOFTWARE\Microsoft\DirectplayNATHelp\DPNHUPnP"; Name="UPnPMode"; Value=2},
        
        # Event log max sizes (1GB)
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security"; Name="MaxSize"; Value=1073741824},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application"; Name="MaxSize"; Value=1073741824},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System"; Name="MaxSize"; Value=1073741824},
        
        # Disable anonymous SID enumeration
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RestrictAnonymousSAM"; Value=1},
        
        # Network security: Do not store LM hash
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="NoLMHash"; Value=1},
        
        # Disable remote registry paths
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths"; Name="Machine"; Value=""},
        
        # Screen saver settings
        @{Path="HKCU:\Control Panel\Desktop"; Name="ScreenSaveActive"; Value="1"},
        @{Path="HKCU:\Control Panel\Desktop"; Name="ScreenSaverIsSecure"; Value="1"},
        @{Path="HKCU:\Control Panel\Desktop"; Name="ScreenSaveTimeOut"; Value="600"}
    )
    
    foreach ($setting in $regSettings) {
        if (!(Test-Path $setting.Path)) {
            New-Item -Path $setting.Path -Force | Out-Null
        }
        
        # Handle string vs dword
        if ($setting.Value -is [string]) {
            Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type String -ErrorAction SilentlyContinue
        } else {
            Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type DWord -ErrorAction SilentlyContinue
        }
        Write-Success "Set: $($setting.Name) = $($setting.Value)"
    }
}

function Set-UserRightsAssignment {
    Write-Info "========== USER RIGHTS ASSIGNMENT =========="
    
    Write-Warning "User Rights Assignment requires manual review in secpol.msc"
    Write-Warning "Check these settings:"
    Write-Warning "  - 'Access this computer from network' - Remove unnecessary users"
    Write-Warning "  - 'Deny log on locally' - Add Guest"
    Write-Warning "  - 'Debug programs' - Administrators only or empty"
    Write-Warning "  - 'Act as part of OS' - Should be empty"
    Write-Warning "  - 'Allow log on through Remote Desktop' - Authorized users only"
    Write-Warning "  - 'Deny access to this computer from network' - Add Guest"
}

# ============================================================
# SERVICES
# ============================================================

function Invoke-ServiceAudit {
    Write-Info "========== SERVICE AUDIT =========="
    
    # Dangerous services to disable (with prompts for some)
    $autoDisableServices = @(
        "RemoteRegistry",      # Remote Registry
        "Telnet",              # Telnet
        "tlntsvr",             # Telnet Server
        "SNMP",                # SNMP
        "SNMPTRAP",            # SNMP Trap
        "SSDPSRV",             # SSDP Discovery
        "upnphost",            # UPnP Device Host
        "RpcLocator",          # RPC Locator
        "Browser",             # Computer Browser
        "XboxGipSvc",          # Xbox Accessory Management
        "XblAuthManager",      # Xbox Live Auth Manager
        "XblGameSave",         # Xbox Live Game Save
        "XboxNetApiSvc",       # Xbox Live Networking Service
        "lfsvc",               # Geolocation Service
        "MapsBroker",          # Downloaded Maps Manager
        "SharedAccess",        # Internet Connection Sharing
        "wisvc",               # Windows Insider Service
        "RetailDemo",          # Retail Demo Service
        "DiagTrack",           # Connected User Experiences (Telemetry)
        "dmwappushservice"     # WAP Push Message Routing
    )
    
    # Services that need confirmation before disabling
    $promptDisableServices = @(
        @{Name="TermService"; Desc="Remote Desktop Services"},
        @{Name="WinRM"; Desc="Windows Remote Management"},
        @{Name="RemoteAccess"; Desc="Routing and Remote Access"},
        @{Name="FTPSVC"; Desc="FTP Service"},
        @{Name="W3SVC"; Desc="IIS Web Server"},
        @{Name="SMTPSVC"; Desc="SMTP Service"},
        @{Name="MSSQLSERVER"; Desc="SQL Server"},
        @{Name="SQLSERVERAGENT"; Desc="SQL Server Agent"}
    )
    
    # Auto-disable dangerous services
    foreach ($svcName in $autoDisableServices) {
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
    
    # Prompt for potentially needed services
    foreach ($svcInfo in $promptDisableServices) {
        if ($svcInfo.Name -in $RequiredServices) {
            Write-Info "Skipping required service: $($svcInfo.Name)"
            continue
        }
        
        $svc = Get-Service -Name $svcInfo.Name -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq "Running") {
            Write-Alert "Service running: $($svcInfo.Name) ($($svcInfo.Desc))"
            Write-Host "    Disable this service? (y/n): " -NoNewline -ForegroundColor Yellow
            $response = Read-Host
            if ($response -eq 'y') {
                Stop-Service -Name $svcInfo.Name -Force -ErrorAction SilentlyContinue
                Set-Service -Name $svcInfo.Name -StartupType Disabled -ErrorAction SilentlyContinue
                Write-Success "Disabled service: $($svcInfo.Name)"
            }
        }
    }
    
    # Ensure critical services are running
    $criticalServices = @(
        "wuauserv",            # Windows Update
        "WinDefend",           # Windows Defender
        "MpsSvc",              # Windows Firewall
        "EventLog",            # Windows Event Log
        "Dnscache",            # DNS Client
        "BITS",                # Background Intelligent Transfer
        "CryptSvc",            # Cryptographic Services
        "Winmgmt",             # WMI
        "Schedule",            # Task Scheduler
        "SamSs"                # Security Accounts Manager
    )
    
    foreach ($svcName in $criticalServices) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc) {
            if ($svc.Status -ne "Running") {
                Start-Service -Name $svcName -ErrorAction SilentlyContinue
                Write-Success "Started critical service: $svcName"
            }
            Set-Service -Name $svcName -StartupType Automatic -ErrorAction SilentlyContinue
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
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogMaxSizeKilobytes 16384
    Write-Success "Firewall logging enabled"
    
    # Disable notifications for blocked connections (reduces noise)
    Set-NetFirewallProfile -Profile Domain,Public,Private -NotifyOnListen False
    
    # Review and disable suspicious inbound rules
    Write-Info "Reviewing inbound rules..."
    $suspiciousRules = Get-NetFirewallRule -Direction Inbound -Enabled True -ErrorAction SilentlyContinue | Where-Object {
        $_.DisplayName -match "game|torrent|remote|vnc|teamviewer|anydesk|logmein" -or
        $_.DisplayName -match "ftp|telnet|tftp|netcat|nc64|ncat" -or
        $_.DisplayName -match "utorrent|bittorrent|vuze|limewire|emule|kazaa"
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
    
    # List all enabled inbound rules for review
    Write-Info "All enabled inbound rules:"
    Get-NetFirewallRule -Direction Inbound -Enabled True | 
        Select-Object DisplayName, Profile | 
        Sort-Object DisplayName |
        Format-Table -AutoSize
}

# ============================================================
# REMOTE DESKTOP HARDENING
# ============================================================

function Set-RDPSecurity {
    Write-Info "========== REMOTE DESKTOP HARDENING =========="
    
    $rdpService = Get-Service -Name "TermService" -ErrorAction SilentlyContinue
    
    if ($rdpService -and $rdpService.Status -eq "Running") {
        Write-Warning "Remote Desktop is enabled"
        
        # Enable Network Level Authentication (NLA)
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1
        Write-Success "Network Level Authentication (NLA) enabled"
        
        # Set encryption level to High
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'MinEncryptionLevel' -Value 3
        Write-Success "RDP encryption set to High"
        
        # Disable clipboard redirection (optional)
        Write-Host "Disable clipboard redirection for RDP? (y/n): " -NoNewline -ForegroundColor Yellow
        $response = Read-Host
        if ($response -eq 'y') {
            $tsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
            if (!(Test-Path $tsPath)) { New-Item -Path $tsPath -Force | Out-Null }
            Set-ItemProperty -Path $tsPath -Name 'fDisableClip' -Value 1
            Write-Success "Clipboard redirection disabled"
        }
        
        # Disable drive redirection (optional)
        Write-Host "Disable drive redirection for RDP? (y/n): " -NoNewline -ForegroundColor Yellow
        $response = Read-Host
        if ($response -eq 'y') {
            $tsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
            if (!(Test-Path $tsPath)) { New-Item -Path $tsPath -Force | Out-Null }
            Set-ItemProperty -Path $tsPath -Name 'fDisableCdm' -Value 1
            Write-Success "Drive redirection disabled"
        }
        
        # Set idle timeout
        $tsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        if (!(Test-Path $tsPath)) {
            New-Item -Path $tsPath -Force | Out-Null
        }
        Set-ItemProperty -Path $tsPath -Name 'MaxIdleTime' -Value 900000  # 15 minutes in milliseconds
        Set-ItemProperty -Path $tsPath -Name 'MaxDisconnectionTime' -Value 60000  # 1 minute
        Write-Success "RDP timeout settings configured"
        
    } else {
        Write-Success "Remote Desktop is not running"
    }
}

# ============================================================
# WINDOWS DEFENDER
# ============================================================

function Set-DefenderConfiguration {
    Write-Info "========== WINDOWS DEFENDER =========="
    
    # Check if Defender is available
    $defender = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
    if (!$defender) {
        Write-Warning "Windows Defender service not found (may be using third-party AV)"
        return
    }
    
    # Enable real-time protection
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
    Write-Success "Real-time protection enabled"
    
    # Enable behavior monitoring
    Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue
    Write-Success "Behavior monitoring enabled"
    
    # Enable IOAV protection (scans downloaded files)
    Set-MpPreference -DisableIOAVProtection $false -ErrorAction SilentlyContinue
    Write-Success "IOAV protection enabled"
    
    # Enable cloud protection
    Set-MpPreference -MAPSReporting Advanced -ErrorAction SilentlyContinue
    Set-MpPreference -SubmitSamplesConsent SendAllSamples -ErrorAction SilentlyContinue
    Write-Success "Cloud protection enabled"
    
    # Enable PUA protection
    Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue
    Write-Success "PUA protection enabled"
    
    # Enable network protection
    Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction SilentlyContinue
    Write-Success "Network protection enabled"
    
    # Enable controlled folder access (ransomware protection)
    Write-Host "Enable Controlled Folder Access (Ransomware Protection)? (y/n): " -NoNewline -ForegroundColor Yellow
    $response = Read-Host
    if ($response -eq 'y') {
        Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue
        Write-Success "Controlled folder access enabled"
    }
    
    # Enable attack surface reduction rules
    $asrRules = @(
        "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550",  # Block executable content from email
        "D4F940AB-401B-4EFC-AADC-AD5F3C50688A",  # Block Office apps from creating child processes
        "3B576869-A4EC-4529-8536-B80A7769E899",  # Block Office apps from creating executable content
        "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84",  # Block Office apps from injecting code
        "D3E037E1-3EB8-44C8-A917-57927947596D",  # Block JavaScript/VBScript from launching executables
        "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC",  # Block execution of potentially obfuscated scripts
        "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B",  # Block Win32 API calls from Office macros
        "01443614-CD74-433A-B99E-2ECDC07BFC25",  # Block executable files unless they meet criteria
        "C1DB55AB-C21A-4637-BB3F-A12568109D35",  # Block untrusted/unsigned processes from USB
        "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2",  # Block credential stealing from LSASS
        "D1E49AAC-8F56-4280-B9BA-993A6D77406C",  # Block process creations from PSExec/WMI
        "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4",  # Block untrusted programs from removable drives
        "26190899-1602-49E8-8B27-EB1D0A1CE869",  # Block Office from creating child processes
        "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C",  # Block Adobe Reader from creating child processes
        "E6DB77E5-3DF2-4CF1-B95A-636979351E5B"   # Block persistence through WMI
    )
    
    Write-Host "Enable Attack Surface Reduction rules? (y/n): " -NoNewline -ForegroundColor Yellow
    $response = Read-Host
    if ($response -eq 'y') {
        foreach ($rule in $asrRules) {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $rule -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue
        }
        Write-Success "ASR rules enabled"
    }
    
    # Check for exclusions (attackers add malware paths here)
    $exclusions = Get-MpPreference
    if ($exclusions.ExclusionPath -or $exclusions.ExclusionProcess -or $exclusions.ExclusionExtension) {
        Write-Alert "Defender exclusions found:"
        if ($exclusions.ExclusionPath) {
            Write-Alert "  Paths:"
            foreach ($path in $exclusions.ExclusionPath) {
                Write-Alert "    - $path"
            }
        }
        if ($exclusions.ExclusionProcess) {
            Write-Alert "  Processes:"
            foreach ($proc in $exclusions.ExclusionProcess) {
                Write-Alert "    - $proc"
            }
        }
        if ($exclusions.ExclusionExtension) {
            Write-Alert "  Extensions:"
            foreach ($ext in $exclusions.ExclusionExtension) {
                Write-Alert "    - $ext"
            }
        }
        
        Write-Host "Remove all exclusions? (y/n): " -NoNewline -ForegroundColor Yellow
        $response = Read-Host
        if ($response -eq 'y') {
            if ($exclusions.ExclusionPath) {
                foreach ($path in $exclusions.ExclusionPath) {
                    Remove-MpPreference -ExclusionPath $path
                }
            }
            if ($exclusions.ExclusionProcess) {
                foreach ($proc in $exclusions.ExclusionProcess) {
                    Remove-MpPreference -ExclusionProcess $proc
                }
            }
            if ($exclusions.ExclusionExtension) {
                foreach ($ext in $exclusions.ExclusionExtension) {
                    Remove-MpPreference -ExclusionExtension $ext
                }
            }
            Write-Success "Removed all exclusions"
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
        
        if ($SearchResult.Updates.Count -gt 0) {
            Write-Host "Install updates now? (y/n): " -NoNewline -ForegroundColor Yellow
            $installResponse = Read-Host
            if ($installResponse -eq 'y') {
                Write-Info "Installing updates..."
                $UpdatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl
                foreach ($Update in $SearchResult.Updates) {
                    $UpdatesToInstall.Add($Update) | Out-Null
                }
                $Installer = $UpdateSession.CreateUpdateInstaller()
                $Installer.Updates = $UpdatesToInstall
                $InstallResult = $Installer.Install()
                Write-Success "Updates installed. Reboot may be required."
            }
        }
    }
}

# ============================================================
# PROHIBITED SOFTWARE
# ============================================================

function Find-ProhibitedSoftware {
    Write-Info "========== PROHIBITED SOFTWARE SCAN =========="
    
    # Patterns for prohibited software
    $prohibitedPatterns = @(
        # Hacking tools
        "*wireshark*",
        "*nmap*",
        "*cain*",
        "*abel*",
        "*keylogger*",
        "*metasploit*",
        "*john*",
        "*hashcat*",
        "*aircrack*",
        "*burp*",
        "*netcat*",
        "*ncat*",
        "*ophcrack*",
        "*mimikatz*",
        "*responder*",
        "*hydra*",
        "*sqlmap*",
        "*nikto*",
        "*zenmap*",
        
        # P2P / Torrents
        "*utorrent*",
        "*bittorrent*",
        "*vuze*",
        "*limewire*",
        "*kazaa*",
        "*emule*",
        "*frostwire*",
        "*qbittorrent*",
        "*deluge*",
        "*transmission*",
        "*tixati*",
        
        # Games
        "*steam*",
        "*origin*",
        "*epicgames*",
        "*minecraft*",
        "*fortnite*",
        "*league of legends*",
        "*roblox*",
        "*blizzard*",
        "*battle.net*",
        "*gog galaxy*",
        "*uplay*",
        
        # Remote access (suspicious)
        "*teamviewer*",
        "*anydesk*",
        "*logmein*",
        "*ammyy*",
        "*ultraviewer*",
        "*rustdesk*",
        "*supremo*",
        
        # Media players (often prohibited)
        "*vlc*",
        "*kodi*",
        "*plex*",
        "*popcorn time*",
        
        # VPN (may be prohibited)
        "*nordvpn*",
        "*expressvpn*",
        "*hotspot shield*",
        "*tunnelbear*",
        "*windscribe*",
        
        # Potentially unwanted
        "*ccleaner*",
        "*driver booster*",
        "*iobit*"
    )
    
    # Check for required programs that shouldn't be flagged
    $filteredPatterns = $prohibitedPatterns | Where-Object {
        $pattern = $_
        $isRequired = $false
        foreach ($required in $RequiredPrograms) {
            if ($pattern -like "*$required*") {
                $isRequired = $true
                break
            }
        }
        -not $isRequired
    }
    
    # Check installed programs
    $installedApps = @()
    $installedApps += Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue
    $installedApps += Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue
    $installedApps += Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue
    
    foreach ($pattern in $filteredPatterns) {
        $found = $installedApps | Where-Object { $_.DisplayName -like $pattern }
        foreach ($app in $found) {
            Write-Alert "Prohibited software: $($app.DisplayName)"
            Write-Warning "  Location: $($app.InstallLocation)"
            Write-Warning "  Uninstall: $($app.UninstallString)"
        }
    }
    
    # Check for PuTTY separately (may be legitimate)
    $putty = $installedApps | Where-Object { $_.DisplayName -like "*putty*" }
    if ($putty) {
        Write-Warning "PuTTY found (may be legitimate if SSH is required): $($putty.DisplayName)"
    }
    
    # Scan common directories for suspicious executables
    Write-Info "Scanning for suspicious files..."
    
    $scanPaths = @(
        "C:\Users\*\Desktop",
        "C:\Users\*\Downloads",
        "C:\Users\*\Documents",
        "C:\Users\*\AppData\Local\Temp",
        "C:\Temp",
        "C:\Windows\Temp",
        "C:\ProgramData"
    )
    
    $suspiciousExtensions = @("*.exe", "*.bat", "*.cmd", "*.ps1", "*.vbs", "*.js", "*.msi", "*.scr", "*.hta")
    $suspiciousNames = @("*hack*", "*crack*", "*keygen*", "*patch*", "*loader*", "*cheat*", "*exploit*", "*payload*", "*shell*", "*backdoor*", "*trojan*", "*rat*", "*nc.exe", "*nc64*", "*ncat*", "*netcat*", "*mimikatz*", "*pwdump*", "*procdump*")
    
    foreach ($scanPath in $scanPaths) {
        foreach ($ext in $suspiciousExtensions) {
            $files = Get-ChildItem -Path $scanPath -Filter $ext -Recurse -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                # Check against suspicious names
                $isSuspicious = $false
                foreach ($name in $suspiciousNames) {
                    if ($file.Name -like $name) {
                        $isSuspicious = $true
                        break
                    }
                }
                if ($isSuspicious) {
                    Write-Alert "Suspicious file: $($file.FullName)"
                } elseif ($file.DirectoryName -match "Temp|Downloads") {
                    Write-Warning "File in suspicious location: $($file.FullName)"
                }
            }
        }
    }
    
    # Check for media files (often prohibited)
    Write-Info "Scanning for media files..."
    $mediaExtensions = @("*.mp3", "*.mp4", "*.avi", "*.mkv", "*.mov", "*.flac", "*.wav")
    foreach ($scanPath in @("C:\Users\*\Desktop", "C:\Users\*\Downloads", "C:\Users\*\Documents", "C:\Users\*\Music", "C:\Users\*\Videos")) {
        foreach ($ext in $mediaExtensions) {
            $files = Get-ChildItem -Path $scanPath -Filter $ext -Recurse -ErrorAction SilentlyContinue | Select-Object -First 10
            foreach ($file in $files) {
                Write-Warning "Media file: $($file.FullName)"
            }
        }
    }
}

# ============================================================
# SHARES
# ============================================================

function Invoke-ShareAudit {
    Write-Info "========== SHARE AUDIT =========="
    
    $shares = Get-SmbShare | Where-Object { $_.Name -notmatch '^\$' -and $_.Name -ne "IPC$" }
    
    if ($shares) {
        foreach ($share in $shares) {
            Write-Warning "Share found: $($share.Name) -> $($share.Path)"
            $perms = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue
            foreach ($perm in $perms) {
                Write-Warning "  $($perm.AccountName): $($perm.AccessRight)"
                
                # Alert on Everyone or Anonymous access
                if ($perm.AccountName -match "Everyone|Anonymous|Guest") {
                    Write-Alert "  DANGEROUS: $($perm.AccountName) has access!"
                }
            }
            
            Write-Host "    Remove this share? (y/n): " -NoNewline -ForegroundColor Yellow
            $response = Read-Host
            if ($response -eq 'y') {
                Remove-SmbShare -Name $share.Name -Force
                Write-Success "Removed share: $($share.Name)"
            }
        }
    } else {
        Write-Success "No non-administrative shares found"
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
            
            # Check for suspicious actions
            if ($action.Execute -match "powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32") {
                Write-Alert "  SUSPICIOUS: Uses scripting engine!"
            }
            if ($action.Arguments -match "hidden|bypass|encoded|downloadstring|iex|invoke") {
                Write-Alert "  SUSPICIOUS: Potentially malicious arguments!"
            }
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
        "PowerShell-V2",
        "MicrosoftWindowsPowerShellV2",
        "MicrosoftWindowsPowerShellV2Root",
        "Internet-Explorer-Optional-amd64",
        "WorkFolders-Client",
        "WindowsMediaPlayer"
    )
    
    foreach ($feature in $dangerousFeatures) {
        $installed = Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction SilentlyContinue
        if ($installed -and $installed.State -eq "Enabled") {
            Write-Alert "Dangerous feature enabled: $feature"
            Write-Host "    Disable? (y/n): " -NoNewline -ForegroundColor Yellow
            $response = Read-Host
            if ($response -eq 'y') {
                Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -ErrorAction SilentlyContinue
                Write-Success "Disabled feature: $feature"
            }
        }
    }
    
    # Check for Server features if applicable
    $isServer = (Get-WmiObject Win32_OperatingSystem).ProductType -ne 1
    if ($isServer) {
        Write-Info "Installed Server Roles:"
        Get-WindowsFeature | Where-Object { $_.Installed -eq $true -and $_.FeatureType -eq "Role" } | ForEach-Object {
            Write-Info "  - $($_.DisplayName)"
        }
        
        Write-Info "Installed Server Features:"
        Get-WindowsFeature | Where-Object { $_.Installed -eq $true -and $_.FeatureType -eq "Feature" } | ForEach-Object {
            Write-Info "  - $($_.DisplayName)"
        }
    }
}

# ============================================================
# HOSTS FILE CHECK
# ============================================================

function Invoke-HostsFileAudit {
    Write-Info "========== HOSTS FILE AUDIT =========="
    
    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    
    if (Test-Path $hostsPath) {
        $content = Get-Content $hostsPath | Where-Object { 
            $_ -notmatch '^\s*#' -and 
            $_.Trim() -ne '' -and
            $_ -notmatch '^\s*$'
        }
        
        if ($content) {
            Write-Alert "Non-comment entries found in hosts file:"
            foreach ($line in $content) {
                # Check for suspicious redirects
                if ($line -match "google|microsoft|windows|update|security|antivirus|defender") {
                    Write-Alert "  SUSPICIOUS: $line"
                } else {
                    Write-Warning "  $line"
                }
            }
            
            Write-Host "View full hosts file? (y/n): " -NoNewline -ForegroundColor Yellow
            $response = Read-Host
            if ($response -eq 'y') {
                Get-Content $hostsPath
            }
            
            Write-Host "Reset hosts file to default? (y/n): " -NoNewline -ForegroundColor Yellow
            $response = Read-Host
            if ($response -eq 'y') {
                $defaultHosts = @"
# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#	127.0.0.1       localhost
#	::1             localhost
"@
                Set-Content -Path $hostsPath -Value $defaultHosts -Force
                Write-Success "Hosts file reset to default"
            }
        } else {
            Write-Success "Hosts file is clean (only comments/defaults)"
        }
    }
}

# ============================================================
# STARTUP PROGRAMS
# ============================================================

function Invoke-StartupAudit {
    Write-Info "========== STARTUP PROGRAMS AUDIT =========="
    
    $startupPaths = @(
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; Desc="HKLM Run"},
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"; Desc="HKLM RunOnce"},
        @{Path="HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"; Desc="HKLM Run (32-bit)"},
        @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; Desc="HKCU Run"},
        @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"; Desc="HKCU RunOnce"},
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"; Desc="Shell Folders"},
        @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"; Desc="User Shell Folders"}
    )
    
    foreach ($regPath in $startupPaths) {
        if (Test-Path $regPath.Path) {
            $items = Get-ItemProperty $regPath.Path -ErrorAction SilentlyContinue
            $props = $items.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }
            
            if ($props) {
                Write-Info "$($regPath.Desc):"
                foreach ($prop in $props) {
                    $isSuspicious = $false
                    $value = $prop.Value
                    
                    # Check for suspicious patterns
                    if ($value -match "temp|appdata\\local\\temp|downloads|public" -and $value -match "\.exe|\.bat|\.cmd|\.vbs|\.ps1") {
                        $isSuspicious = $true
                    }
                    if ($value -match "powershell.*-enc|-encoded|downloadstring|iex|bypass|hidden") {
                        $isSuspicious = $true
                    }
                    if ($value -match "wscript|cscript|mshta|rundll32.*javascript|regsvr32.*/s.*/u") {
                        $isSuspicious = $true
                    }
                    
                    if ($isSuspicious) {
                        Write-Alert "  SUSPICIOUS: $($prop.Name) = $value"
                    } else {
                        Write-Warning "  $($prop.Name) = $value"
                    }
                }
            }
        }
    }
    
    # Check startup folders
    $startupFolders = @(
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    
    foreach ($folder in $startupFolders) {
        if (Test-Path $folder) {
            $files = Get-ChildItem $folder -ErrorAction SilentlyContinue
            if ($files) {
                Write-Info "Startup folder: $folder"
                foreach ($file in $files) {
                    if ($file.Extension -match "\.exe|\.bat|\.cmd|\.vbs|\.ps1|\.lnk") {
                        Write-Warning "  $($file.Name)"
                        
                        # If it's a shortcut, show target
                        if ($file.Extension -eq ".lnk") {
                            try {
                                $shell = New-Object -ComObject WScript.Shell
                                $shortcut = $shell.CreateShortcut($file.FullName)
                                Write-Warning "    Target: $($shortcut.TargetPath)"
                            } catch {}
                        }
                    }
                }
            }
        }
    }
    
    # Offer to review Task Manager startup
    Write-Info "Also check Task Manager > Startup tab for additional items"
}

# ============================================================
# DNS SETTINGS CHECK
# ============================================================

function Invoke-DNSAudit {
    Write-Info "========== DNS SETTINGS AUDIT =========="
    
    # Get all network adapters
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    
    foreach ($adapter in $adapters) {
        Write-Info "Adapter: $($adapter.Name)"
        
        $dnsServers = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        
        if ($dnsServers.ServerAddresses) {
            foreach ($dns in $dnsServers.ServerAddresses) {
                # Check for known safe DNS servers
                $knownSafe = @("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "208.67.222.222", "208.67.220.220")
                $isLocalRange = $dns -match "^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)"
                
                if ($dns -in $knownSafe) {
                    Write-Success "  DNS: $dns (Known safe - Google/Cloudflare/Quad9/OpenDNS)"
                } elseif ($isLocalRange -or $dns -eq "127.0.0.1") {
                    Write-Info "  DNS: $dns (Local/Internal)"
                } else {
                    Write-Warning "  DNS: $dns (Unknown - verify this is legitimate)"
                }
            }
        } else {
            Write-Info "  DNS: DHCP assigned"
        }
    }
    
    # Check for DNS cache poisoning indicators
    Write-Info "Checking DNS cache for suspicious entries..."
    $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object {
        $_.Entry -match "google|microsoft|windows|update|security|bank"
    }
    
    foreach ($entry in $dnsCache) {
        # Check if IP looks suspicious (private IP for public domain)
        if ($entry.Data -match "^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)" -and $entry.Entry -notmatch "local|internal") {
            Write-Alert "Suspicious DNS cache entry: $($entry.Entry) -> $($entry.Data)"
        }
    }
}

# ============================================================
# BROWSER SECURITY
# ============================================================

function Invoke-BrowserAudit {
    Write-Info "========== BROWSER SECURITY AUDIT =========="
    
    # Internet Explorer / Edge settings
    Write-Info "Checking Internet Explorer/Edge security zones..."
    
    $internetZone = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
    if (Test-Path $internetZone) {
        $settings = Get-ItemProperty $internetZone -ErrorAction SilentlyContinue
        
        # Check ActiveX settings (1200 = Run ActiveX)
        if ($settings.'1200' -eq 0) {
            Write-Alert "IE: ActiveX controls enabled in Internet Zone!"
        }
        # Check scripting (1400 = Active scripting)
        if ($settings.'1400' -eq 0) {
            Write-Warning "IE: Active scripting enabled in Internet Zone"
        }
    }
    
    # Check for suspicious browser extensions
    Write-Info "Checking for browser extensions..."
    
    # Chrome extensions
    $chromeExtPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"
    if (Test-Path $chromeExtPath) {
        $extensions = Get-ChildItem $chromeExtPath -Directory -ErrorAction SilentlyContinue
        Write-Info "Chrome extensions found: $($extensions.Count)"
        Write-Warning "  Manual review recommended at: $chromeExtPath"
    }
    
    # Firefox extensions
    $firefoxPath = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path $firefoxPath) {
        Write-Warning "Firefox profile found - check extensions manually"
    }
    
    # Edge extensions
    $edgeExtPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"
    if (Test-Path $edgeExtPath) {
        $extensions = Get-ChildItem $edgeExtPath -Directory -ErrorAction SilentlyContinue
        Write-Info "Edge extensions found: $($extensions.Count)"
        Write-Warning "  Manual review recommended at: $edgeExtPath"
    }
    
    # Check homepage hijacking
    Write-Info "Checking browser homepages..."
    
    $ieHomepage = (Get-ItemProperty "HKCU:\Software\Microsoft\Internet Explorer\Main" -Name "Start Page" -ErrorAction SilentlyContinue)."Start Page"
    if ($ieHomepage) {
        if ($ieHomepage -notmatch "msn\.com|microsoft\.com|bing\.com|google\.com|about:blank") {
            Write-Warning "IE Homepage: $ieHomepage"
        }
    }
    
    # Secure IE settings
    Write-Host "Harden Internet Explorer settings? (y/n): " -NoNewline -ForegroundColor Yellow
    $response = Read-Host
    if ($response -eq 'y') {
        # Disable ActiveX in Internet Zone
        Set-ItemProperty -Path $internetZone -Name "1200" -Value 3 -Type DWord -ErrorAction SilentlyContinue
        # Enable Protected Mode
        Set-ItemProperty -Path $internetZone -Name "2500" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        # Enable SmartScreen
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\PhishingFilter" -Name "EnabledV9" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Write-Success "IE security settings hardened"
    }
}

# ============================================================
# FIREFOX HARDENING (CyberPatriot specific)
# ============================================================

function Set-FirefoxSecurity {
    Write-Info "========== FIREFOX SECURITY =========="
    
    $firefoxProfiles = "$env:APPDATA\Mozilla\Firefox\Profiles"
    
    if (Test-Path $firefoxProfiles) {
        $profiles = Get-ChildItem $firefoxProfiles -Directory
        
        foreach ($profile in $profiles) {
            $prefsFile = Join-Path $profile.FullName "prefs.js"
            $userPrefsFile = Join-Path $profile.FullName "user.js"
            
            Write-Info "Found Firefox profile: $($profile.Name)"
            
            # Create user.js with secure settings
            $secureSettings = @"
// CyberPatriot Firefox Hardening
user_pref("privacy.donottrackheader.enabled", true);
user_pref("browser.safebrowsing.malware.enabled", true);
user_pref("browser.safebrowsing.phishing.enabled", true);
user_pref("browser.safebrowsing.downloads.enabled", true);
user_pref("browser.safebrowsing.downloads.remote.block_potentially_unwanted", true);
user_pref("browser.safebrowsing.downloads.remote.block_uncommon", true);
user_pref("network.cookie.cookieBehavior", 1);
user_pref("privacy.trackingprotection.enabled", true);
user_pref("geo.enabled", false);
user_pref("browser.search.suggest.enabled", false);
user_pref("browser.formfill.enable", false);
user_pref("signon.rememberSignons", false);
user_pref("network.prefetch-next", false);
user_pref("network.dns.disablePrefetch", true);
user_pref("browser.send_pings", false);
user_pref("dom.battery.enabled", false);
user_pref("media.navigator.enabled", false);
user_pref("webgl.disabled", true);
"@
            
            Write-Host "Apply secure Firefox settings to this profile? (y/n): " -NoNewline -ForegroundColor Yellow
            $response = Read-Host
            if ($response -eq 'y') {
                Set-Content -Path $userPrefsFile -Value $secureSettings -Force
                Write-Success "Firefox security settings applied to: $($profile.Name)"
            }
        }
        
        Write-Warning "Remember to also:"
        Write-Warning "  1. Update Firefox (Help > About Firefox)"
        Write-Warning "  2. Review installed extensions"
        Write-Warning "  3. Check Settings > Privacy & Security"
    } else {
        Write-Info "Firefox not installed or no profiles found"
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
    
    # Disable Guest account
    Disable-LocalUser -Name "NoGuest" -ErrorAction SilentlyContinue
    Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    Write-Success "Guest account disabled"
    
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
    
    # Disable Sticky Keys backdoor
    Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Value "506" -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\ToggleKeys" -Name "Flags" -Value "58" -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "Flags" -Value "122" -ErrorAction SilentlyContinue
    Write-Success "Accessibility shortcuts disabled (Sticky Keys backdoor prevention)"
    
    # Disable Windows Script Host (may break legitimate scripts)
    Write-Host "Disable Windows Script Host? (y/n): " -NoNewline -ForegroundColor Yellow
    $response = Read-Host
    if ($response -eq 'y') {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Write-Success "Windows Script Host disabled"
    }
}

# ============================================================
# FORENSICS HELPER
# ============================================================

function Get-ForensicsInfo {
    Write-Info "========== FORENSICS HELPER =========="
    
    Write-Info "Last 10 Security Events (Logon Failures - Event 4625):"
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 10 -ErrorAction SilentlyContinue | 
        ForEach-Object {
            Write-Warning "  $($_.TimeCreated): Failed logon attempt"
        }
    
    Write-Info "Last 10 Successful Logons (Event 4624):"
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} -MaxEvents 10 -ErrorAction SilentlyContinue |
        ForEach-Object {
            $xml = [xml]$_.ToXml()
            $user = $xml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" } | Select-Object -ExpandProperty '#text'
            Write-Info "  $($_.TimeCreated): $user"
        }
    
    Write-Info "Last 10 Installed Programs (Event 11707):"
    Get-WinEvent -FilterHashtable @{LogName='Application';Id=11707} -MaxEvents 10 -ErrorAction SilentlyContinue |
        ForEach-Object {
            Write-Warning "  $($_.TimeCreated): $($_.Message.Substring(0, [Math]::Min(100, $_.Message.Length)))..."
        }
    
    Write-Info "Last 10 User Creations (Event 4720):"
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4720} -MaxEvents 10 -ErrorAction SilentlyContinue |
        ForEach-Object {
            Write-Alert "  $($_.TimeCreated): User created"
        }
    
    Write-Info "Last 10 Group Membership Changes (Event 4728/4732):"
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=@(4728,4732)} -MaxEvents 10 -ErrorAction SilentlyContinue |
        ForEach-Object {
            Write-Alert "  $($_.TimeCreated): Group membership changed"
        }
    
    Write-Info "Listening Ports:"
    Get-NetTCPConnection -State Listen | 
        Select-Object LocalAddress, LocalPort, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}} | 
        Sort-Object LocalPort |
        Format-Table -AutoSize
    
    Write-Info "Established Connections (external):"
    Get-NetTCPConnection -State Established | 
        Where-Object { $_.RemoteAddress -notmatch "^(127\.|::1|0\.0\.0\.0)" } |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}} |
        Format-Table -AutoSize
    
    Write-Info "Running Processes (non-system paths):"
    Get-Process | Where-Object { $_.Path -and $_.Path -notmatch "Windows|Program Files|System32" } |
        Select-Object Name, Path, Id | 
        Format-Table -AutoSize
    
    Write-Info "Recently Modified Files (last 24 hours) in suspicious locations:"
    $recentFiles = Get-ChildItem -Path "C:\Users\*\Downloads", "C:\Users\*\Desktop", "C:\Windows\Temp", "C:\Temp" -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-24) -and $_.Extension -match "\.exe|\.bat|\.ps1|\.vbs|\.dll" }
    foreach ($file in $recentFiles | Select-Object -First 20) {
        Write-Warning "  $($file.LastWriteTime): $($file.FullName)"
    }
}

# ============================================================
# MAIN MENU
# ============================================================

function Show-Menu {
    Clear-Host
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "  CYBERPATRIOT WINDOWS HARDENING SCRIPT" -ForegroundColor Cyan
    Write-Host "         Complete Edition v2.1" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1]  Run ALL Hardening (Recommended)" -ForegroundColor Green
    Write-Host ""
    Write-Host "  --- User & Authentication ---" -ForegroundColor Magenta
    Write-Host "  [2]  User Audit" -ForegroundColor Yellow
    Write-Host "  [3]  Admin Group Audit" -ForegroundColor Yellow
    Write-Host "  [4]  Password Policy" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  --- System Security ---" -ForegroundColor Magenta
    Write-Host "  [5]  Audit Policy" -ForegroundColor Yellow
    Write-Host "  [6]  Security Options (Registry)" -ForegroundColor Yellow
    Write-Host "  [7]  Service Audit" -ForegroundColor Yellow
    Write-Host "  [8]  Firewall Configuration" -ForegroundColor Yellow
    Write-Host "  [9]  RDP Security" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  --- Malware & Software ---" -ForegroundColor Magenta
    Write-Host "  [10] Windows Defender" -ForegroundColor Yellow
    Write-Host "  [11] Windows Update" -ForegroundColor Yellow
    Write-Host "  [12] Prohibited Software Scan" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  --- Configuration Audit ---" -ForegroundColor Magenta
    Write-Host "  [13] Share Audit" -ForegroundColor Yellow
    Write-Host "  [14] Scheduled Task Audit" -ForegroundColor Yellow
    Write-Host "  [15] Features/Roles Audit" -ForegroundColor Yellow
    Write-Host "  [16] Hosts File Audit" -ForegroundColor Yellow
    Write-Host "  [17] Startup Programs Audit" -ForegroundColor Yellow
    Write-Host "  [18] DNS Settings Audit" -ForegroundColor Yellow
    Write-Host "  [19] Browser Security Audit" -ForegroundColor Yellow
    Write-Host "  [20] Firefox Security" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  --- Tools ---" -ForegroundColor Magenta
    Write-Host "  [21] Quick Wins" -ForegroundColor Yellow
    Write-Host "  [22] Forensics Helper" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  [0]  Exit" -ForegroundColor Red
    Write-Host ""
}

function Invoke-AllHardening {
    Write-Info "Running complete hardening sequence..."
    Write-Info "=========================================="
    
    Invoke-UserAudit
    Invoke-AdminAudit
    Set-PasswordPolicy
    Set-AuditPolicy
    Set-SecurityOptions
    Invoke-ServiceAudit
    Set-FirewallConfiguration
    Set-RDPSecurity
    Set-DefenderConfiguration
    Set-WindowsUpdate
    Find-ProhibitedSoftware
    Invoke-ShareAudit
    Invoke-ScheduledTaskAudit
    Invoke-FeatureAudit
    Invoke-HostsFileAudit
    Invoke-StartupAudit
    Invoke-DNSAudit
    Invoke-BrowserAudit
    Set-FirefoxSecurity
    Invoke-QuickWins
    
    Write-Info "=========================================="
    Write-Info "HARDENING COMPLETE"
    Write-Info "Log saved to: $LogFile"
    Write-Info "=========================================="
    Write-Warning ""
    Write-Warning "MANUAL CHECKS STILL REQUIRED:"
    Write-Warning "  1. Review Local Security Policy (secpol.msc)"
    Write-Warning "  2. Check User Rights Assignment"
    Write-Warning "  3. Review browser extensions manually"
    Write-Warning "  4. Check for hidden files/folders"
    Write-Warning "  5. Review README for any specific requirements"
    Write-Warning "  6. Answer Forensics Questions on desktop"
    Write-Warning ""
}

# ============================================================
# MAIN EXECUTION
# ============================================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  IMPORTANT: UPDATE CONFIGURATION FIRST!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Before running, edit the script to set:" -ForegroundColor Yellow
Write-Host "    - `$AuthorizedUsers" -ForegroundColor White
Write-Host "    - `$AuthorizedAdmins" -ForegroundColor White
Write-Host "    - `$RequiredServices" -ForegroundColor White
Write-Host "    - `$RequiredPrograms" -ForegroundColor White
Write-Host ""
Write-Host "  Press Enter to continue or Ctrl+C to exit..." -ForegroundColor Gray
Read-Host

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
        "9"  { Set-RDPSecurity }
        "10" { Set-DefenderConfiguration }
        "11" { Set-WindowsUpdate }
        "12" { Find-ProhibitedSoftware }
        "13" { Invoke-ShareAudit }
        "14" { Invoke-ScheduledTaskAudit }
        "15" { Invoke-FeatureAudit }
        "16" { Invoke-HostsFileAudit }
        "17" { Invoke-StartupAudit }
        "18" { Invoke-DNSAudit }
        "19" { Invoke-BrowserAudit }
        "20" { Set-FirefoxSecurity }
        "21" { Invoke-QuickWins }
        "22" { Get-ForensicsInfo }
        "0"  { Write-Host "Exiting..."; break }
        default { Write-Host "Invalid option" -ForegroundColor Red }
    }
    
    if ($choice -ne "0") {
        Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
        Read-Host
    }
} while ($choice -ne "0")
