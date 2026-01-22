#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CyberPatriot Windows Server 2022 Hardening Script - Complete Edition
.DESCRIPTION
    Comprehensive hardening script optimized for Windows Server 2022
    Covers users, policies, services, firewall, startup, hosts file, IIS, AD, and more
.NOTES
    Run as Administrator
    Review README before running - update $AuthorizedUsers and $AuthorizedAdmins
.VERSION
    3.0 - Server 2022 Optimized Edition with Full Fixes
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
    # Example: "Spooler" if print services are required
    # Example: "DNS" if DNS server role is required
    # Example: "NTDS" if Active Directory is required
)

$RequiredPrograms = @(
    # Add programs that should NOT be flagged as prohibited
    # Example: "putty" if SSH client is needed
)

$RequiredFeatures = @(
    # Add Windows features that should NOT be disabled
    # Example: "Web-Server" if IIS is required
    # Example: "AD-Domain-Services" if this is a domain controller
)

# ============================================================
# OS DETECTION AND COMPATIBILITY
# ============================================================

$OS = Get-CimInstance Win32_OperatingSystem
$IsServer = $OS.ProductType -ne 1
$OSBuild = $OS.BuildNumber
$OSCaption = $OS.Caption

# Detect if Domain Controller
$IsDomainController = $false
try {
    $dcCheck = Get-CimInstance -ClassName Win32_ComputerSystem
    if ($dcCheck.DomainRole -ge 4) {
        $IsDomainController = $true
    }
} catch {}

# Detect installed roles
$InstalledRoles = @()
if ($IsServer) {
    try {
        $InstalledRoles = (Get-WindowsFeature | Where-Object { $_.Installed -and $_.FeatureType -eq "Role" }).Name
    } catch {}
}

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
# INITIALIZATION
# ============================================================

function Show-SystemInfo {
    Write-Info "========== SYSTEM INFORMATION =========="
    Write-Info "OS: $OSCaption"
    Write-Info "Build: $OSBuild"
    Write-Info "Server OS: $IsServer"
    Write-Info "Domain Controller: $IsDomainController"
    
    if ($InstalledRoles.Count -gt 0) {
        Write-Info "Installed Roles:"
        foreach ($role in $InstalledRoles) {
            Write-Info "  - $role"
        }
    }
    
    Write-Info "Computer Name: $env:COMPUTERNAME"
    Write-Info "Domain/Workgroup: $((Get-CimInstance Win32_ComputerSystem).Domain)"
    Write-Info "========================================="
}

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
    
    # Check DefaultAccount
    $defaultAcct = Get-LocalUser -Name "DefaultAccount" -ErrorAction SilentlyContinue
    if ($defaultAcct -and $defaultAcct.Enabled) {
        Disable-LocalUser -Name "DefaultAccount"
        Write-Success "Disabled DefaultAccount"
    }
    
    # Check for hidden/suspicious users
    Write-Info "Checking for hidden/suspicious users..."
    $suspiciousUsers = Get-LocalUser | Where-Object {
        $_.Name -match '\$$' -or           # Ends with $
        $_.Name -match '^\.' -or           # Starts with .
        ($_.Name -match 'admin' -and $_.Name -ne 'Administrator') -or
        $_.Name -match 'test|temp|backup|service|user\d+|svc_|sql|ftp|www|web|mysql|postgres|oracle|guest'
    }
    
    foreach ($user in $suspiciousUsers) {
        if ($user.Name -notin $AuthorizedUsers) {
            Write-Alert "Suspicious user found: $($user.Name) (Enabled: $($user.Enabled))"
        }
    }
    
    # Check for users with password never expires
    Write-Info "Checking password expiration settings..."
    $neverExpires = Get-LocalUser | Where-Object { $_.PasswordNeverExpires -eq $true -and $_.Enabled -eq $true }
    foreach ($user in $neverExpires) {
        if ($user.Name -ne "Administrator") {
            Write-Warning "Password never expires: $($user.Name)"
        }
    }
    
    # Check for users with no password required
    $noPasswordRequired = Get-LocalUser | Where-Object { $_.PasswordRequired -eq $false -and $_.Enabled -eq $true }
    foreach ($user in $noPasswordRequired) {
        Write-Alert "No password required: $($user.Name)"
    }
}

function Invoke-AdminAudit {
    Write-Info "========== ADMIN GROUP AUDIT =========="
    
    $adminGroup = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
    
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
    $privilegedGroups = @(
        "Remote Desktop Users", 
        "Backup Operators", 
        "Power Users", 
        "Network Configuration Operators",
        "Remote Management Users",
        "Hyper-V Administrators",
        "Access Control Assistance Operators",
        "Distributed COM Users",
        "Event Log Readers",
        "IIS_IUSRS",
        "Performance Log Users",
        "Performance Monitor Users",
        "Print Operators",
        "Server Operators",
        "Replicator"
    )
    
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
    net accounts /minpwlen:14 /maxpwage:60 /minpwage:1 /uniquepw:24 /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30
    
    Write-Success "Password policy configured:"
    Write-Success "  - Minimum length: 14"
    Write-Success "  - Maximum age: 60 days"
    Write-Success "  - Minimum age: 1 day"
    Write-Success "  - History: 24 passwords"
    Write-Success "  - Lockout threshold: 5 attempts"
    Write-Success "  - Lockout duration: 30 minutes"
    
    # Export current security policy, modify, and import
    $secEditPath = "$env:TEMP\secpol.cfg"
    secedit /export /cfg $secEditPath /quiet
    
    # Modify password complexity
    $content = Get-Content $secEditPath
    $content = $content -replace 'PasswordComplexity = 0', 'PasswordComplexity = 1'
    $content = $content -replace 'ClearTextPassword = 1', 'ClearTextPassword = 0'
    $content | Set-Content $secEditPath
    
    # Import modified policy
    secedit /configure /db secedit.sdb /cfg $secEditPath /quiet
    Remove-Item $secEditPath -ErrorAction SilentlyContinue
    Remove-Item "$env:TEMP\secedit.sdb" -ErrorAction SilentlyContinue
    
    Write-Success "Password complexity enabled"
    Write-Success "Reversible encryption disabled"
}

# ============================================================
# AUDIT POLICY
# ============================================================

function Set-AuditPolicy {
    Write-Info "========== AUDIT POLICY =========="
    
    # Enable comprehensive auditing using auditpol
    $auditCategories = @(
        "Account Logon",
        "Account Management",
        "Logon/Logoff",
        "Object Access",
        "Policy Change",
        "Privilege Use",
        "System",
        "DS Access",
        "Detailed Tracking"
    )
    
    foreach ($category in $auditCategories) {
        auditpol /set /category:"$category" /success:enable /failure:enable 2>$null
        Write-Success "Enabled auditing: $category"
    }
    
    # Enable specific subcategories for better coverage
    $subcategories = @(
        "Credential Validation",
        "Security Group Management",
        "User Account Management",
        "Process Creation",
        "Logon",
        "Special Logon",
        "Removable Storage",
        "Central Policy Staging",
        "Audit Policy Change",
        "Authentication Policy Change",
        "Sensitive Privilege Use",
        "Security State Change",
        "Security System Extension",
        "System Integrity"
    )
    
    foreach ($sub in $subcategories) {
        auditpol /set /subcategory:"$sub" /success:enable /failure:enable 2>$null
    }
    
    # Enable command line auditing in process creation events
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    if (!(Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord
    Write-Success "Command line auditing enabled for process creation"
}

# ============================================================
# LOCAL SECURITY POLICY
# ============================================================

function Set-SecurityOptions {
    Write-Info "========== SECURITY OPTIONS =========="
    
    # These require registry modifications
    $regSettings = @(
        # Don't display last username
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="DontDisplayLastUserName"; Value=1; Type="DWord"},
        
        # Require Ctrl+Alt+Del for logon
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="DisableCAD"; Value=0; Type="DWord"},
        
        # UAC settings
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableLUA"; Value=1; Type="DWord"},
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="ConsentPromptBehaviorAdmin"; Value=2; Type="DWord"},
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="ConsentPromptBehaviorUser"; Value=0; Type="DWord"},
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="PromptOnSecureDesktop"; Value=1; Type="DWord"},
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="FilterAdministratorToken"; Value=1; Type="DWord"},
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableVirtualization"; Value=1; Type="DWord"},
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableInstallerDetection"; Value=1; Type="DWord"},
        
        # Machine inactivity limit (900 seconds = 15 min)
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="InactivityTimeoutSecs"; Value=900; Type="DWord"},
        
        # Disable anonymous enumeration
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RestrictAnonymous"; Value=1; Type="DWord"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RestrictAnonymousSAM"; Value=1; Type="DWord"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="EveryoneIncludesAnonymous"; Value=0; Type="DWord"},
        
        # LAN Manager authentication level (NTLMv2 only)
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="LmCompatibilityLevel"; Value=5; Type="DWord"},
        
        # Do not store LAN Manager hash
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="NoLMHash"; Value=1; Type="DWord"},
        
        # SMB signing
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="RequireSecuritySignature"; Value=1; Type="DWord"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="RequireSecuritySignature"; Value=1; Type="DWord"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="EnableSecuritySignature"; Value=1; Type="DWord"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="EnableSecuritySignature"; Value=1; Type="DWord"},
        
        # Disable autorun/autoplay
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoAutorun"; Value=1; Type="DWord"},
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoDriveTypeAutoRun"; Value=255; Type="DWord"},
        @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoDriveTypeAutoRun"; Value=255; Type="DWord"},
        
        # Disable remote assistance
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"; Name="fAllowToGetHelp"; Value=0; Type="DWord"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"; Name="fAllowFullControl"; Value=0; Type="DWord"},
        
        # Disable admin shares (be careful - may break some management tools)
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="AutoShareWks"; Value=0; Type="DWord"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="AutoShareServer"; Value=0; Type="DWord"},
        
        # Limit cached logons (credential caching) - set to 2 for servers that may be offline
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Name="CachedLogonsCount"; Value=2; Type="DWord"},
        
        # Disable LLMNR
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"; Name="EnableMulticast"; Value=0; Type="DWord"},
        
        # Disable NetBIOS over TCP/IP
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"; Name="NodeType"; Value=2; Type="DWord"},
        
        # Disable WPAD
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad"; Name="WpadOverride"; Value=1; Type="DWord"},
        
        # Disable WDigest (clear-text passwords in memory)
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"; Name="UseLogonCredential"; Value=0; Type="DWord"},
        
        # Enable LSA Protection
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RunAsPPL"; Value=1; Type="DWord"},
        
        # Safe DLL search mode
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"; Name="SafeDllSearchMode"; Value=1; Type="DWord"},
        
        # Windows SmartScreen
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name="EnableSmartScreen"; Value=1; Type="DWord"},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name="ShellSmartScreenLevel"; Value="Block"; Type="String"},
        
        # Legal notice banner
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="LegalNoticeCaption"; Value="AUTHORIZED ACCESS ONLY"; Type="String"},
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="LegalNoticeText"; Value="This system is for authorized use only. All activities may be monitored and recorded. Unauthorized access is prohibited and may result in disciplinary action and/or criminal prosecution."; Type="String"},
        
        # Event log max sizes (1GB)
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security"; Name="MaxSize"; Value=1073741824; Type="DWord"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application"; Name="MaxSize"; Value=1073741824; Type="DWord"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System"; Name="MaxSize"; Value=1073741824; Type="DWord"},
        
        # Prevent anonymous access to named pipes and shares
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="RestrictNullSessAccess"; Value=1; Type="DWord"},
        
        # Screen saver settings
        @{Path="HKCU:\Control Panel\Desktop"; Name="ScreenSaveActive"; Value="1"; Type="String"},
        @{Path="HKCU:\Control Panel\Desktop"; Name="ScreenSaverIsSecure"; Value="1"; Type="String"},
        @{Path="HKCU:\Control Panel\Desktop"; Name="ScreenSaveTimeOut"; Value="600"; Type="String"},
        
        # Disable Windows Error Reporting
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"; Name="Disabled"; Value=1; Type="DWord"},
        
        # Disable Windows Script Host (careful - may break legitimate scripts)
        # @{Path="HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings"; Name="Enabled"; Value=0; Type="DWord"},
        
        # Disable PowerShell v2 engine via registry
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"; Name="EnableScripts"; Value=1; Type="DWord"},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"; Name="ExecutionPolicy"; Value="RemoteSigned"; Type="String"},
        
        # Disable mDNS
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"; Name="EnableMDNS"; Value=0; Type="DWord"},
        
        # Credential Guard prerequisites (Server 2022 supports this)
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"; Name="EnableVirtualizationBasedSecurity"; Value=1; Type="DWord"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"; Name="RequirePlatformSecurityFeatures"; Value=1; Type="DWord"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="LsaCfgFlags"; Value=1; Type="DWord"},
        
        # Remote Desktop hardening
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"; Name="fDenyTSConnections"; Value=1; Type="DWord"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"; Name="UserAuthentication"; Value=1; Type="DWord"},
        
        # Disable IPv6 components (if not needed)
        # @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"; Name="DisabledComponents"; Value=255; Type="DWord"},
        
        # Disable DCOM
        @{Path="HKLM:\SOFTWARE\Microsoft\Ole"; Name="EnableDCOM"; Value="N"; Type="String"},
        
        # Disable WinRM if not needed
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"; Name="AllowAutoConfig"; Value=0; Type="DWord"}
    )
    
    foreach ($setting in $regSettings) {
        try {
            if (!(Test-Path $setting.Path)) {
                New-Item -Path $setting.Path -Force | Out-Null
            }
            
            Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type $setting.Type -ErrorAction Stop
            Write-Success "Set: $($setting.Name) = $($setting.Value)"
        } catch {
            Write-Warning "Failed to set: $($setting.Name) - $($_.Exception.Message)"
        }
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
    Write-Warning "  - 'Deny access to this computer from network' - Add Guest, Anonymous"
    Write-Warning "  - 'Create a token object' - Should be empty"
    Write-Warning "  - 'Take ownership of files' - Administrators only"
    Write-Warning "  - 'Bypass traverse checking' - Review carefully"
}

# ============================================================
# SMB HARDENING
# ============================================================

function Set-SMBSecurity {
    Write-Info "========== SMB HARDENING =========="
    
    # Disable SMBv1 explicitly
    Write-Info "Disabling SMBv1..."
    
    try {
        # Server component
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop
        Write-Success "SMBv1 Server disabled"
    } catch {
        Write-Warning "Could not disable SMBv1 via Set-SmbServerConfiguration: $($_.Exception.Message)"
    }
    
    # Disable SMBv1 feature (Server 2022)
    if ($IsServer) {
        try {
            $smb1Feature = Get-WindowsFeature -Name "FS-SMB1" -ErrorAction SilentlyContinue
            if ($smb1Feature -and $smb1Feature.Installed) {
                Write-Alert "SMBv1 feature is installed!"
                Write-Host "    Remove SMBv1 feature? (y/n): " -NoNewline -ForegroundColor Yellow
                $response = Read-Host
                if ($response -eq 'y') {
                    Remove-WindowsFeature -Name "FS-SMB1" -ErrorAction SilentlyContinue
                    Write-Success "SMBv1 feature removed (requires restart)"
                }
            } else {
                Write-Success "SMBv1 feature not installed"
            }
        } catch {
            Write-Warning "Could not check SMBv1 feature: $($_.Exception.Message)"
        }
    }
    
    # Additional SMB hardening
    try {
        Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
        Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
        Set-SmbServerConfiguration -EnableSecuritySignature $true -Force
        Set-SmbServerConfiguration -EncryptData $true -Force
        Set-SmbServerConfiguration -RejectUnencryptedAccess $true -Force
        
        Write-Success "SMB encryption and signing enforced"
    } catch {
        Write-Warning "Some SMB settings could not be applied"
    }
    
    # Disable SMB compression (CVE-2020-0796 mitigation)
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "DisableCompression" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Write-Success "SMB compression disabled"
}

# ============================================================
# TLS/SSL HARDENING
# ============================================================

function Set-TLSSecurity {
    Write-Info "========== TLS/SSL HARDENING =========="
    
    # Disable insecure protocols
    $insecureProtocols = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")
    
    foreach ($protocol in $insecureProtocols) {
        # Server
        $serverPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server"
        if (!(Test-Path $serverPath)) {
            New-Item -Path $serverPath -Force | Out-Null
        }
        Set-ItemProperty -Path $serverPath -Name "Enabled" -Value 0 -Type DWord
        Set-ItemProperty -Path $serverPath -Name "DisabledByDefault" -Value 1 -Type DWord
        
        # Client
        $clientPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Client"
        if (!(Test-Path $clientPath)) {
            New-Item -Path $clientPath -Force | Out-Null
        }
        Set-ItemProperty -Path $clientPath -Name "Enabled" -Value 0 -Type DWord
        Set-ItemProperty -Path $clientPath -Name "DisabledByDefault" -Value 1 -Type DWord
        
        Write-Success "Disabled: $protocol"
    }
    
    # Enable TLS 1.2 and 1.3
    $secureProtocols = @("TLS 1.2", "TLS 1.3")
    
    foreach ($protocol in $secureProtocols) {
        # Server
        $serverPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server"
        if (!(Test-Path $serverPath)) {
            New-Item -Path $serverPath -Force | Out-Null
        }
        Set-ItemProperty -Path $serverPath -Name "Enabled" -Value 1 -Type DWord
        Set-ItemProperty -Path $serverPath -Name "DisabledByDefault" -Value 0 -Type DWord
        
        # Client
        $clientPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Client"
        if (!(Test-Path $clientPath)) {
            New-Item -Path $clientPath -Force | Out-Null
        }
        Set-ItemProperty -Path $clientPath -Name "Enabled" -Value 1 -Type DWord
        Set-ItemProperty -Path $clientPath -Name "DisabledByDefault" -Value 0 -Type DWord
        
        Write-Success "Enabled: $protocol"
    }
    
    # Disable weak ciphers
    $weakCiphers = @(
        "DES 56/56",
        "NULL",
        "RC2 40/128",
        "RC2 56/128",
        "RC2 128/128",
        "RC4 40/128",
        "RC4 56/128",
        "RC4 64/128",
        "RC4 128/128",
        "Triple DES 168"
    )
    
    foreach ($cipher in $weakCiphers) {
        $cipherPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$cipher"
        if (!(Test-Path $cipherPath)) {
            New-Item -Path $cipherPath -Force | Out-Null
        }
        Set-ItemProperty -Path $cipherPath -Name "Enabled" -Value 0 -Type DWord
        Write-Success "Disabled cipher: $cipher"
    }
    
    # Enable strong ciphers
    $strongCiphers = @(
        "AES 128/128",
        "AES 256/256"
    )
    
    foreach ($cipher in $strongCiphers) {
        $cipherPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$cipher"
        if (!(Test-Path $cipherPath)) {
            New-Item -Path $cipherPath -Force | Out-Null
        }
        Set-ItemProperty -Path $cipherPath -Name "Enabled" -Value 1 -Type DWord
        Write-Success "Enabled cipher: $cipher"
    }
    
    # .NET Framework TLS settings
    $netFxPaths = @(
        "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727",
        "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319"
    )
    
    foreach ($path in $netFxPaths) {
        if (Test-Path $path) {
            Set-ItemProperty -Path $path -Name "SchUseStrongCrypto" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $path -Name "SystemDefaultTlsVersions" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        }
    }
    Write-Success ".NET Framework configured for strong crypto"
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
        "dmwappushservice",    # WAP Push Message Routing
        "WMPNetworkSvc",       # Windows Media Player Network Sharing
        "icssvc",              # Windows Mobile Hotspot Service
        "PhoneSvc",            # Phone Service
        "WpcMonSvc",           # Parental Controls
        "WerSvc",              # Windows Error Reporting
        "Fax",                 # Fax
        "TabletInputService",  # Touch Keyboard and Handwriting Panel
        "lltdsvc",             # Link-Layer Topology Discovery Mapper
        "MSiSCSI",             # Microsoft iSCSI Initiator
        "QWAVE",               # Quality Windows Audio Video Experience
        "wlidsvc",             # Microsoft Account Sign-in Assistant
        "simptcp",             # Simple TCP/IP Services
        "sacsvr",              # Special Administration Console Helper
        "SNMPTRAP"             # SNMP Trap
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
        @{Name="SQLSERVERAGENT"; Desc="SQL Server Agent"},
        @{Name="Spooler"; Desc="Print Spooler (PrintNightmare risk)"},
        @{Name="ssh-agent"; Desc="OpenSSH Authentication Agent"},
        @{Name="sshd"; Desc="OpenSSH Server"},
        @{Name="LanmanServer"; Desc="Server (File Sharing)"},
        @{Name="IISADMIN"; Desc="IIS Admin Service"},
        @{Name="MSFTPSVC"; Desc="FTP Publishing Service"},
        @{Name="TlntSvr"; Desc="Telnet Server"}
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
    
    # Special handling for Print Spooler (PrintNightmare)
    if ("Spooler" -notin $RequiredServices) {
        $spooler = Get-Service -Name "Spooler" -ErrorAction SilentlyContinue
        if ($spooler -and $spooler.Status -eq "Running") {
            Write-Alert "Print Spooler is running (PrintNightmare vulnerability)"
            Write-Host "    Disable Print Spooler? (y/n): " -NoNewline -ForegroundColor Yellow
            $response = Read-Host
            if ($response -eq 'y') {
                Stop-Service -Name "Spooler" -Force -ErrorAction SilentlyContinue
                Set-Service -Name "Spooler" -StartupType Disabled -ErrorAction SilentlyContinue
                Write-Success "Print Spooler disabled"
            } else {
                # If keeping Spooler, apply mitigations
                Write-Info "Applying Print Spooler mitigations..."
                # Disable Point and Print
                $printPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
                if (!(Test-Path $printPath)) { New-Item -Path $printPath -Force | Out-Null }
                Set-ItemProperty -Path $printPath -Name "RestrictDriverInstallationToAdministrators" -Value 1 -Type DWord
                Set-ItemProperty -Path $printPath -Name "NoWarningNoElevationOnInstall" -Value 0 -Type DWord
                Set-ItemProperty -Path $printPath -Name "UpdatePromptSettings" -Value 0 -Type DWord
                Write-Success "Print Spooler mitigations applied"
            }
        }
    }
    
    # Prompt for potentially needed services
    foreach ($svcInfo in $promptDisableServices) {
        if ($svcInfo.Name -in $RequiredServices) {
            Write-Info "Skipping required service: $($svcInfo.Name)"
            continue
        }
        
        if ($svcInfo.Name -eq "Spooler") { continue }  # Already handled above
        
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
        "SamSs",               # Security Accounts Manager
        "RpcSs",               # Remote Procedure Call
        "RpcEptMapper",        # RPC Endpoint Mapper
        "LSM",                 # Local Session Manager
        "SENS",                # System Event Notification Service
        "TrustedInstaller",    # Windows Modules Installer
        "PlugPlay",            # Plug and Play
        "Power",               # Power
        "ProfSvc",             # User Profile Service
        "nsi",                 # Network Store Interface Service
        "Netlogon",            # Netlogon (if domain joined)
        "BFE",                 # Base Filtering Engine
        "Dhcp"                 # DHCP Client
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
    
    # Check for services running as LocalSystem that shouldn't be
    Write-Info "Checking for potentially dangerous service accounts..."
    $dangerousServiceAccounts = Get-WmiObject Win32_Service | Where-Object {
        $_.StartName -eq "LocalSystem" -and 
        $_.Name -notin @("wuauserv", "TrustedInstaller", "Schedule", "EventLog", "MpsSvc", "WinDefend", "RpcSs", "LSM") -and
        $_.State -eq "Running"
    } | Select-Object Name, DisplayName, PathName -First 20
    
    foreach ($svc in $dangerousServiceAccounts) {
        if ($svc.PathName -notmatch "Windows|System32|svchost") {
            Write-Warning "Service running as LocalSystem: $($svc.DisplayName) ($($svc.Name))"
            Write-Warning "  Path: $($svc.PathName)"
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
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogMaxSizeKilobytes 32768
    Write-Success "Firewall logging enabled (32MB log)"
    
    # Disable notifications for blocked connections (reduces noise)
    Set-NetFirewallProfile -Profile Domain,Public,Private -NotifyOnListen False
    
    # Block all inbound by default on public
    Set-NetFirewallProfile -Profile Public -AllowInboundRules False
    Write-Success "Public profile: All inbound blocked"
    
    # Review and disable suspicious inbound rules
    Write-Info "Reviewing inbound rules..."
    $suspiciousRules = Get-NetFirewallRule -Direction Inbound -Enabled True -ErrorAction SilentlyContinue | Where-Object {
        $_.DisplayName -match "game|torrent|remote|vnc|teamviewer|anydesk|logmein" -or
        $_.DisplayName -match "ftp|telnet|tftp|netcat|nc64|ncat" -or
        $_.DisplayName -match "utorrent|bittorrent|vuze|limewire|emule|kazaa" -or
        $_.DisplayName -match "meterpreter|reverse|shell|beacon|cobalt|mimikatz"
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
    
    # Create blocking rules for common attack vectors
    Write-Info "Creating security firewall rules..."
    
    # Block common malware ports
    $blockPorts = @(
        @{Port=23; Protocol="TCP"; Name="Block Telnet"},
        @{Port=69; Protocol="UDP"; Name="Block TFTP"},
        @{Port=135; Protocol="TCP"; Name="Block RPC"},
        @{Port=137; Protocol="UDP"; Name="Block NetBIOS-NS"},
        @{Port=138; Protocol="UDP"; Name="Block NetBIOS-DGM"},
        @{Port=139; Protocol="TCP"; Name="Block NetBIOS-SSN"},
        @{Port=445; Protocol="TCP"; Name="Block SMB"},
        @{Port=593; Protocol="TCP"; Name="Block HTTP-RPC"},
        @{Port=4444; Protocol="TCP"; Name="Block Metasploit Default"},
        @{Port=5800; Protocol="TCP"; Name="Block VNC-HTTP"},
        @{Port=5900; Protocol="TCP"; Name="Block VNC"}
    )
    
    Write-Host "Create blocking rules for common attack ports? (y/n): " -NoNewline -ForegroundColor Yellow
    $response = Read-Host
    if ($response -eq 'y') {
        foreach ($portInfo in $blockPorts) {
            $existingRule = Get-NetFirewallRule -DisplayName $portInfo.Name -ErrorAction SilentlyContinue
            if (!$existingRule) {
                New-NetFirewallRule -DisplayName $portInfo.Name -Direction Inbound -Action Block -Protocol $portInfo.Protocol -LocalPort $portInfo.Port -Profile Any -ErrorAction SilentlyContinue | Out-Null
                Write-Success "Created rule: $($portInfo.Name)"
            }
        }
    }
    
    # List all enabled inbound rules for review
    Write-Info "Summary of enabled inbound rules:"
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
    
    if ("TermService" -notin $RequiredServices) {
        Write-Host "Disable Remote Desktop completely? (y/n): " -NoNewline -ForegroundColor Yellow
        $response = Read-Host
        if ($response -eq 'y') {
            Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 1
            Stop-Service -Name "TermService" -Force -ErrorAction SilentlyContinue
            Set-Service -Name "TermService" -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Success "Remote Desktop disabled"
            return
        }
    }
    
    if ($rdpService) {
        Write-Info "Hardening Remote Desktop settings..."
        
        # Enable Network Level Authentication (NLA)
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1
        Write-Success "Network Level Authentication (NLA) enabled"
        
        # Set encryption level to High
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'MinEncryptionLevel' -Value 3
        Write-Success "RDP encryption set to High"
        
        # Set security layer to SSL/TLS
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'SecurityLayer' -Value 2
        Write-Success "RDP security layer set to SSL/TLS"
        
        # Terminal Services settings
        $tsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        if (!(Test-Path $tsPath)) { New-Item -Path $tsPath -Force | Out-Null }
        
        # Disable clipboard redirection
        Set-ItemProperty -Path $tsPath -Name 'fDisableClip' -Value 1
        Write-Success "Clipboard redirection disabled"
        
        # Disable drive redirection
        Set-ItemProperty -Path $tsPath -Name 'fDisableCdm' -Value 1
        Write-Success "Drive redirection disabled"
        
        # Disable LPT port redirection
        Set-ItemProperty -Path $tsPath -Name 'fDisableLPT' -Value 1
        
        # Disable COM port redirection
        Set-ItemProperty -Path $tsPath -Name 'fDisableCcm' -Value 1
        
        # Disable printer redirection
        Set-ItemProperty -Path $tsPath -Name 'fDisableCpm' -Value 1
        
        # Set idle timeout (15 minutes)
        Set-ItemProperty -Path $tsPath -Name 'MaxIdleTime' -Value 900000
        
        # Set disconnect timeout (1 minute)
        Set-ItemProperty -Path $tsPath -Name 'MaxDisconnectionTime' -Value 60000
        
        # Set total session time limit (8 hours for active, 1 hour for disconnected)
        Set-ItemProperty -Path $tsPath -Name 'MaxConnectionTime' -Value 28800000
        
        # Delete temp folders on exit
        Set-ItemProperty -Path $tsPath -Name 'DeleteTempDirsOnExit' -Value 1
        
        # Use temp folders per session
        Set-ItemProperty -Path $tsPath -Name 'PerSessionTempDir' -Value 1
        
        Write-Success "RDP hardening complete"
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
    
    # Ensure Defender service is running
    if ($defender.Status -ne "Running") {
        Start-Service -Name "WinDefend" -ErrorAction SilentlyContinue
        Set-Service -Name "WinDefend" -StartupType Automatic -ErrorAction SilentlyContinue
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
    
    # Enable script scanning
    Set-MpPreference -DisableScriptScanning $false -ErrorAction SilentlyContinue
    Write-Success "Script scanning enabled"
    
    # Enable email scanning
    Set-MpPreference -DisableEmailScanning $false -ErrorAction SilentlyContinue
    Write-Success "Email scanning enabled"
    
    # Enable archive scanning
    Set-MpPreference -DisableArchiveScanning $false -ErrorAction SilentlyContinue
    Write-Success "Archive scanning enabled"
    
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
    
    # Set scan schedule
    Set-MpPreference -ScanScheduleDay Everyday -ErrorAction SilentlyContinue
    Set-MpPreference -ScanScheduleTime 02:00:00 -ErrorAction SilentlyContinue
    Write-Success "Daily scan scheduled for 2 AM"
    
    # Enable block at first sight
    Set-MpPreference -DisableBlockAtFirstSeen $false -ErrorAction SilentlyContinue
    Write-Success "Block at first sight enabled"
    
    # Set cloud timeout
    Set-MpPreference -CloudBlockLevel High -ErrorAction SilentlyContinue
    Set-MpPreference -CloudExtendedTimeout 50 -ErrorAction SilentlyContinue
    Write-Success "Cloud block level set to High"
    
    # Enable Attack Surface Reduction rules
    $asrRules = @(
        @{Id="BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550"; Desc="Block executable content from email"},
        @{Id="D4F940AB-401B-4EFC-AADC-AD5F3C50688A"; Desc="Block Office apps from creating child processes"},
        @{Id="3B576869-A4EC-4529-8536-B80A7769E899"; Desc="Block Office apps from creating executable content"},
        @{Id="75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84"; Desc="Block Office apps from injecting code"},
        @{Id="D3E037E1-3EB8-44C8-A917-57927947596D"; Desc="Block JavaScript/VBScript from launching executables"},
        @{Id="5BEB7EFE-FD9A-4556-801D-275E5FFC04CC"; Desc="Block execution of potentially obfuscated scripts"},
        @{Id="92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B"; Desc="Block Win32 API calls from Office macros"},
        @{Id="01443614-CD74-433A-B99E-2ECDC07BFC25"; Desc="Block executable files unless they meet criteria"},
        @{Id="C1DB55AB-C21A-4637-BB3F-A12568109D35"; Desc="Block untrusted/unsigned processes from USB"},
        @{Id="9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2"; Desc="Block credential stealing from LSASS"},
        @{Id="D1E49AAC-8F56-4280-B9BA-993A6D77406C"; Desc="Block process creations from PSExec/WMI"},
        @{Id="B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4"; Desc="Block untrusted programs from removable drives"},
        @{Id="26190899-1602-49E8-8B27-EB1D0A1CE869"; Desc="Block Office from creating child processes"},
        @{Id="7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C"; Desc="Block Adobe Reader from creating child processes"},
        @{Id="E6DB77E5-3DF2-4CF1-B95A-636979351E5B"; Desc="Block persistence through WMI"},
        @{Id="56a863a9-875e-4185-98a7-b882c64b5ce5"; Desc="Block abuse of exploited vulnerable signed drivers"},
        @{Id="33ddedf1-c6e0-47cb-833e-de6133960387"; Desc="Block rebooting machine in safe mode"},
        @{Id="c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb"; Desc="Block use of copied or impersonated system tools"}
    )
    
    Write-Host "Enable Attack Surface Reduction (ASR) rules? (y/n): " -NoNewline -ForegroundColor Yellow
    $response = Read-Host
    if ($response -eq 'y') {
        foreach ($rule in $asrRules) {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $rule.Id -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue
            Write-Success "ASR: $($rule.Desc)"
        }
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
                    Remove-MpPreference -ExclusionPath $path -ErrorAction SilentlyContinue
                }
            }
            if ($exclusions.ExclusionProcess) {
                foreach ($proc in $exclusions.ExclusionProcess) {
                    Remove-MpPreference -ExclusionProcess $proc -ErrorAction SilentlyContinue
                }
            }
            if ($exclusions.ExclusionExtension) {
                foreach ($ext in $exclusions.ExclusionExtension) {
                    Remove-MpPreference -ExclusionExtension $ext -ErrorAction SilentlyContinue
                }
            }
            Write-Success "Removed all exclusions"
        }
    } else {
        Write-Success "No suspicious exclusions found"
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
    Set-ItemProperty -Path $WUPath -Name "NoAutoRebootWithLoggedOnUsers" -Value 0 -Type DWord
    
    Write-Success "Windows Update configured for automatic updates"
    
    # Enable Microsoft Update (includes Office, SQL, etc.)
    $ServiceManager = New-Object -ComObject Microsoft.Update.ServiceManager
    $ServiceManager.AddService2("7971f918-a847-4430-9279-4a52d1efe18d", 7, "") 2>$null
    Write-Success "Microsoft Update enabled"
    
    # Check for updates
    Write-Host "Check for updates now? (y/n): " -NoNewline -ForegroundColor Yellow
    $response = Read-Host
    if ($response -eq 'y') {
        Write-Info "Checking for updates... (this may take a while)"
        try {
            $UpdateSession = New-Object -ComObject Microsoft.Update.Session
            $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
            $SearchResult = $UpdateSearcher.Search("IsInstalled=0")
            Write-Info "Found $($SearchResult.Updates.Count) updates available"
            
            if ($SearchResult.Updates.Count -gt 0) {
                foreach ($update in $SearchResult.Updates | Select-Object -First 10) {
                    Write-Warning "  - $($update.Title)"
                }
                if ($SearchResult.Updates.Count -gt 10) {
                    Write-Warning "  ... and $($SearchResult.Updates.Count - 10) more"
                }
                
                Write-Host "Install updates now? (y/n): " -NoNewline -ForegroundColor Yellow
                $installResponse = Read-Host
                if ($installResponse -eq 'y') {
                    Write-Info "Installing updates..."
                    $UpdatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl
                    foreach ($Update in $SearchResult.Updates) {
                        if ($Update.IsDownloaded) {
                            $UpdatesToInstall.Add($Update) | Out-Null
                        }
                    }
                    if ($UpdatesToInstall.Count -gt 0) {
                        $Installer = $UpdateSession.CreateUpdateInstaller()
                        $Installer.Updates = $UpdatesToInstall
                        $InstallResult = $Installer.Install()
                        Write-Success "Updates installed. Reboot may be required."
                    } else {
                        Write-Info "Downloading updates first..."
                        $Downloader = $UpdateSession.CreateUpdateDownloader()
                        $Downloader.Updates = $SearchResult.Updates
                        $Downloader.Download()
                        Write-Info "Download complete. Run script again to install."
                    }
                }
            }
        } catch {
            Write-Warning "Error checking updates: $($_.Exception.Message)"
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
        "*wireshark*", "*nmap*", "*cain*", "*abel*", "*keylogger*", "*metasploit*",
        "*john*", "*hashcat*", "*aircrack*", "*burp*", "*netcat*", "*ncat*",
        "*ophcrack*", "*mimikatz*", "*responder*", "*hydra*", "*sqlmap*", "*nikto*",
        "*zenmap*", "*maltego*", "*autopsy*", "*volatility*", "*ollydbg*", "*x64dbg*",
        "*immunity*", "*ida pro*", "*ghidra*", "*radare*", "*bloodhound*",
        
        # P2P / Torrents
        "*utorrent*", "*bittorrent*", "*vuze*", "*limewire*", "*kazaa*", "*emule*",
        "*frostwire*", "*qbittorrent*", "*deluge*", "*transmission*", "*tixati*",
        
        # Games
        "*steam*", "*origin*", "*epicgames*", "*minecraft*", "*fortnite*",
        "*league of legends*", "*roblox*", "*blizzard*", "*battle.net*",
        "*gog galaxy*", "*uplay*", "*discord*",
        
        # Remote access (suspicious)
        "*teamviewer*", "*anydesk*", "*logmein*", "*ammyy*", "*ultraviewer*",
        "*rustdesk*", "*supremo*", "*splashtop*", "*connectwise*", "*bomgar*",
        
        # Media players (often prohibited)
        "*vlc*", "*kodi*", "*plex*", "*popcorn time*", "*stremio*",
        
        # VPN (may be prohibited)
        "*nordvpn*", "*expressvpn*", "*hotspot shield*", "*tunnelbear*",
        "*windscribe*", "*protonvpn*", "*cyberghost*", "*surfshark*",
        
        # Potentially unwanted
        "*ccleaner*", "*driver booster*", "*iobit*", "*avast*", "*avg*",
        "*norton*", "*mcafee*"  # Third-party AV may conflict
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
    
    $foundProhibited = @()
    
    foreach ($pattern in $filteredPatterns) {
        $found = $installedApps | Where-Object { $_.DisplayName -like $pattern }
        foreach ($app in $found) {
            Write-Alert "Prohibited software: $($app.DisplayName)"
            Write-Warning "  Location: $($app.InstallLocation)"
            Write-Warning "  Uninstall: $($app.UninstallString)"
            $foundProhibited += $app
        }
    }
    
    # Check for PuTTY separately (may be legitimate)
    $putty = $installedApps | Where-Object { $_.DisplayName -like "*putty*" }
    if ($putty -and "putty" -notin $RequiredPrograms) {
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
        "C:\ProgramData",
        "C:\inetpub\wwwroot"
    )
    
    $suspiciousExtensions = @("*.exe", "*.bat", "*.cmd", "*.ps1", "*.vbs", "*.js", "*.msi", "*.scr", "*.hta", "*.jar")
    $suspiciousNames = @(
        "*hack*", "*crack*", "*keygen*", "*patch*", "*loader*", "*cheat*", "*exploit*",
        "*payload*", "*shell*", "*backdoor*", "*trojan*", "*rat*", "*nc.exe", "*nc64*",
        "*ncat*", "*netcat*", "*mimikatz*", "*pwdump*", "*procdump*", "*lazagne*",
        "*wce*", "*gsecdump*", "*lsadump*", "*secretsdump*", "*psexec*", "*paexec*"
    )
    
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
                    Write-Warning "Executable in temp location: $($file.FullName)"
                }
            }
        }
    }
    
    # Check for media files (often prohibited)
    Write-Host "Scan for media files? (y/n): " -NoNewline -ForegroundColor Yellow
    $response = Read-Host
    if ($response -eq 'y') {
        Write-Info "Scanning for media files..."
        $mediaExtensions = @("*.mp3", "*.mp4", "*.avi", "*.mkv", "*.mov", "*.flac", "*.wav", "*.wmv", "*.m4a")
        foreach ($scanPath in @("C:\Users\*\Desktop", "C:\Users\*\Downloads", "C:\Users\*\Documents", "C:\Users\*\Music", "C:\Users\*\Videos")) {
            foreach ($ext in $mediaExtensions) {
                $files = Get-ChildItem -Path $scanPath -Filter $ext -Recurse -ErrorAction SilentlyContinue | Select-Object -First 20
                foreach ($file in $files) {
                    Write-Warning "Media file: $($file.FullName)"
                }
            }
        }
    }
    
    # Check for alternate data streams (hidden data)
    Write-Info "Checking for Alternate Data Streams (ADS)..."
    $adsLocations = @("C:\Users\*\Desktop", "C:\Users\*\Downloads", "C:\Windows\Temp")
    foreach ($location in $adsLocations) {
        $files = Get-ChildItem -Path $location -Recurse -ErrorAction SilentlyContinue | Get-Item -Stream * -ErrorAction SilentlyContinue | Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' }
        foreach ($file in $files | Select-Object -First 10) {
            Write-Alert "ADS found: $($file.FileName):$($file.Stream)"
        }
    }
}

# ============================================================
# SHARES
# ============================================================

function Invoke-ShareAudit {
    Write-Info "========== SHARE AUDIT =========="
    
    $shares = Get-SmbShare | Where-Object { $_.Name -notmatch '^\w\$$' -and $_.Name -ne "IPC$" -and $_.Name -ne "ADMIN$" }
    
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
    
    # Check null session shares
    Write-Info "Checking null session shares..."
    $nullShares = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "NullSessionShares" -ErrorAction SilentlyContinue).NullSessionShares
    if ($nullShares) {
        Write-Alert "Null session shares found: $($nullShares -join ', ')"
    }
    
    # Check null session pipes
    $nullPipes = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "NullSessionPipes" -ErrorAction SilentlyContinue).NullSessionPipes
    if ($nullPipes) {
        Write-Warning "Null session pipes: $($nullPipes -join ', ')"
    }
}

# ============================================================
# SCHEDULED TASKS
# ============================================================

function Invoke-ScheduledTaskAudit {
    Write-Info "========== SCHEDULED TASK AUDIT =========="
    
    # Get non-Microsoft scheduled tasks
    $tasks = Get-ScheduledTask | Where-Object { 
        $_.TaskPath -notmatch "\\Microsoft\\" -and 
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
            if ($action.Execute -match "powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32|msiexec|certutil") {
                Write-Alert "  SUSPICIOUS: Uses scripting engine or LOLBin!"
            }
            if ($action.Arguments -match "hidden|bypass|encoded|downloadstring|iex|invoke|webclient|bitstransfer|-enc |-e |-ec ") {
                Write-Alert "  SUSPICIOUS: Potentially malicious arguments!"
            }
            if ($action.Execute -match "\\Temp\\|\\AppData\\|\\Downloads\\|\\Public\\") {
                Write-Alert "  SUSPICIOUS: Executes from temp/user directory!"
            }
        }
        
        Write-Host "    Disable this task? (y/n): " -NoNewline -ForegroundColor Yellow
        $response = Read-Host
        if ($response -eq 'y') {
            Disable-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath
            Write-Success "Disabled task: $($task.TaskName)"
        }
    }
    
    # Check for tasks running as SYSTEM
    Write-Info "Tasks running as SYSTEM (review for legitimacy):"
    $systemTasks = Get-ScheduledTask | Where-Object { $_.Principal.UserId -eq "SYSTEM" -and $_.TaskPath -notmatch "\\Microsoft\\" }
    foreach ($task in $systemTasks) {
        Write-Warning "  $($task.TaskPath)$($task.TaskName)"
    }
}

# ============================================================
# FEATURES AND ROLES (Server 2022)
# ============================================================

function Invoke-FeatureAudit {
    Write-Info "========== FEATURES AND ROLES AUDIT =========="
    
    if (!$IsServer) {
        Write-Warning "Not running on Windows Server - using client feature detection"
        # Client-side feature check
        $dangerousClientFeatures = @(
            "TelnetClient",
            "TFTP",
            "SMB1Protocol",
            "SMB1Protocol-Client",
            "SMB1Protocol-Server",
            "MicrosoftWindowsPowerShellV2",
            "MicrosoftWindowsPowerShellV2Root"
        )
        
        foreach ($feature in $dangerousClientFeatures) {
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
        return
    }
    
    # Server feature check
    $dangerousFeatures = @(
        "Telnet-Client",
        "Telnet-Server",
        "TFTP-Client",
        "FS-SMB1",
        "FS-SMB1-CLIENT",
        "FS-SMB1-SERVER",
        "PowerShell-V2",
        "Windows-Defender-Features",  # Check it's installed
        "RSAT-SNMP",
        "Simple-TCPIP"
    )
    
    Write-Info "Checking dangerous features..."
    foreach ($feature in $dangerousFeatures) {
        if ($feature -in $RequiredFeatures) {
            Write-Info "Skipping required feature: $feature"
            continue
        }
        
        $installed = Get-WindowsFeature -Name $feature -ErrorAction SilentlyContinue
        if ($installed -and $installed.Installed) {
            Write-Alert "Dangerous feature installed: $feature ($($installed.DisplayName))"
            Write-Host "    Remove? (y/n): " -NoNewline -ForegroundColor Yellow
            $response = Read-Host
            if ($response -eq 'y') {
                Remove-WindowsFeature -Name $feature -ErrorAction SilentlyContinue
                Write-Success "Removed feature: $feature (may require restart)"
            }
        }
    }
    
    # List installed roles
    Write-Info "Installed Server Roles:"
    $roles = Get-WindowsFeature | Where-Object { $_.Installed -eq $true -and $_.FeatureType -eq "Role" }
    foreach ($role in $roles) {
        Write-Info "  [ROLE] $($role.DisplayName)"
    }
    
    Write-Info "Installed Server Features:"
    $features = Get-WindowsFeature | Where-Object { $_.Installed -eq $true -and $_.FeatureType -eq "Feature" }
    foreach ($feature in $features | Select-Object -First 20) {
        Write-Info "  [FEATURE] $($feature.DisplayName)"
    }
    
    # Check if critical security features are installed
    $requiredSecurityFeatures = @("Windows-Defender", "Windows-Defender-Features")
    foreach ($feature in $requiredSecurityFeatures) {
        $installed = Get-WindowsFeature -Name $feature -ErrorAction SilentlyContinue
        if ($installed -and !$installed.Installed) {
            Write-Alert "Security feature not installed: $feature"
            Write-Host "    Install? (y/n): " -NoNewline -ForegroundColor Yellow
            $response = Read-Host
            if ($response -eq 'y') {
                Install-WindowsFeature -Name $feature -ErrorAction SilentlyContinue
                Write-Success "Installed feature: $feature"
            }
        }
    }
}

# ============================================================
# IIS HARDENING (if installed)
# ============================================================

function Set-IISSecurity {
    Write-Info "========== IIS HARDENING =========="
    
    # Check if IIS is installed
    $iisInstalled = $false
    if ($IsServer) {
        $iisFeature = Get-WindowsFeature -Name "Web-Server" -ErrorAction SilentlyContinue
        $iisInstalled = $iisFeature -and $iisFeature.Installed
    } else {
        $iisFeature = Get-WindowsOptionalFeature -Online -FeatureName "IIS-WebServer" -ErrorAction SilentlyContinue
        $iisInstalled = $iisFeature -and $iisFeature.State -eq "Enabled"
    }
    
    if (!$iisInstalled) {
        Write-Info "IIS is not installed - skipping IIS hardening"
        return
    }
    
    Write-Info "IIS is installed - applying security configuration"
    
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    
    if (!(Get-Module WebAdministration)) {
        Write-Warning "WebAdministration module not available"
        return
    }
    
    # Remove default website if exists
    $defaultSite = Get-Website -Name "Default Web Site" -ErrorAction SilentlyContinue
    if ($defaultSite) {
        Write-Warning "Default Web Site found"
        Write-Host "    Remove Default Web Site? (y/n): " -NoNewline -ForegroundColor Yellow
        $response = Read-Host
        if ($response -eq 'y') {
            Remove-Website -Name "Default Web Site" -ErrorAction SilentlyContinue
            Write-Success "Removed Default Web Site"
        }
    }
    
    # Disable directory browsing globally
    Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -Value false -PSPath IIS:\ -ErrorAction SilentlyContinue
    Write-Success "Directory browsing disabled"
    
    # Remove server header
    $serverHeaderPath = "HKLM:\SOFTWARE\Microsoft\InetStp"
    Set-ItemProperty -Path $serverHeaderPath -Name "RemoveServerHeader" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Write-Success "Server header removal configured"
    
    # Disable WebDAV if not needed
    $webdavModule = Get-WebConfigurationProperty -Filter /system.webServer/modules -Name collection -ErrorAction SilentlyContinue | Where-Object { $_.name -eq "WebDAVModule" }
    if ($webdavModule) {
        Write-Warning "WebDAV module is enabled"
        Write-Host "    Disable WebDAV? (y/n): " -NoNewline -ForegroundColor Yellow
        $response = Read-Host
        if ($response -eq 'y') {
            Remove-WebConfigurationProperty -Filter /system.webServer/modules -Name collection -AtElement @{name='WebDAVModule'} -PSPath IIS:\ -ErrorAction SilentlyContinue
            Write-Success "WebDAV disabled"
        }
    }
    
    # Configure request filtering
    Write-Info "Configuring request filtering..."
    
    # Block dangerous extensions
    $dangerousExtensions = @(".asa", ".asax", ".ascx", ".master", ".skin", ".browser", ".sitemap", ".config", ".cs", ".csproj", ".vb", ".vbproj", ".webinfo", ".licx", ".resx", ".resources", ".mdb", ".vjsproj", ".java", ".jsl", ".ldb", ".dsdgm", ".ssdgm", ".lsad", ".ssmap", ".cd", ".dsprototype", ".lsaprototype", ".sdm", ".sdmDocument", ".mdf", ".ldf", ".ad", ".dd", ".ldd", ".sd", ".adprototype", ".lddprototype", ".exclude", ".refresh", ".compiled", ".msgx", ".vsdisco")
    
    foreach ($ext in $dangerousExtensions) {
        Add-WebConfigurationProperty -Filter /system.webServer/security/requestFiltering/fileExtensions -Name collection -Value @{fileExtension=$ext; allowed='false'} -PSPath IIS:\ -ErrorAction SilentlyContinue
    }
    Write-Success "Dangerous file extensions blocked"
    
    # Set max content length
    Set-WebConfigurationProperty -Filter /system.webServer/security/requestFiltering/requestLimits -Name maxAllowedContentLength -Value 30000000 -PSPath IIS:\ -ErrorAction SilentlyContinue
    Write-Success "Max content length set to 30MB"
    
    # Enable custom errors (hide detailed errors)
    Set-WebConfigurationProperty -Filter /system.web/customErrors -Name mode -Value "RemoteOnly" -PSPath IIS:\ -ErrorAction SilentlyContinue
    Write-Success "Custom errors configured"
    
    # Remove IIS version from headers
    Set-WebConfigurationProperty -Filter /system.webServer/httpProtocol/customHeaders -Name collection -AtElement @{name='X-Powered-By'} -PSPath IIS:\ -ErrorAction SilentlyContinue
    Write-Success "X-Powered-By header removal configured"
    
    # Add security headers
    Write-Info "Adding security headers..."
    $securityHeaders = @(
        @{Name="X-Frame-Options"; Value="SAMEORIGIN"},
        @{Name="X-Content-Type-Options"; Value="nosniff"},
        @{Name="X-XSS-Protection"; Value="1; mode=block"},
        @{Name="Strict-Transport-Security"; Value="max-age=31536000; includeSubDomains"}
    )
    
    foreach ($header in $securityHeaders) {
        Add-WebConfigurationProperty -Filter /system.webServer/httpProtocol/customHeaders -Name collection -Value @{name=$header.Name; value=$header.Value} -PSPath IIS:\ -ErrorAction SilentlyContinue
    }
    Write-Success "Security headers added"
    
    # List all websites and app pools
    Write-Info "Current IIS Sites:"
    Get-Website | ForEach-Object {
        Write-Info "  Site: $($_.Name) - State: $($_.State) - Path: $($_.PhysicalPath)"
    }
    
    Write-Info "Current App Pools:"
    Get-ChildItem IIS:\AppPools | ForEach-Object {
        Write-Info "  Pool: $($_.Name) - State: $($_.State) - Identity: $($_.processModel.identityType)"
    }
    
    # Check for anonymous authentication on sensitive paths
    Write-Info "Checking authentication settings..."
    $sites = Get-Website
    foreach ($site in $sites) {
        $anonAuth = Get-WebConfigurationProperty -Filter /system.webServer/security/authentication/anonymousAuthentication -Name enabled -PSPath "IIS:\Sites\$($site.Name)" -ErrorAction SilentlyContinue
        if ($anonAuth -eq $true) {
            Write-Warning "Anonymous authentication enabled on: $($site.Name)"
        }
    }
}

# ============================================================
# ACTIVE DIRECTORY CHECKS (if Domain Controller)
# ============================================================

function Invoke-ADSecurityAudit {
    Write-Info "========== ACTIVE DIRECTORY SECURITY AUDIT =========="
    
    if (!$IsDomainController) {
        Write-Info "This server is not a Domain Controller - skipping AD audit"
        return
    }
    
    Write-Info "Domain Controller detected - running AD security checks"
    
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
    
    if (!(Get-Module ActiveDirectory)) {
        Write-Warning "ActiveDirectory module not available"
        return
    }
    
    # Check for stale accounts (not logged in for 90 days)
    Write-Info "Checking for stale user accounts..."
    $staleDate = (Get-Date).AddDays(-90)
    $staleUsers = Get-ADUser -Filter {LastLogonDate -lt $staleDate -and Enabled -eq $true} -Properties LastLogonDate -ErrorAction SilentlyContinue
    foreach ($user in $staleUsers | Select-Object -First 20) {
        Write-Warning "Stale account: $($user.SamAccountName) - Last logon: $($user.LastLogonDate)"
    }
    if ($staleUsers.Count -gt 20) {
        Write-Warning "... and $($staleUsers.Count - 20) more stale accounts"
    }
    
    # Check for accounts with password never expires
    Write-Info "Checking for accounts with password never expires..."
    $neverExpires = Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true} -ErrorAction SilentlyContinue
    foreach ($user in $neverExpires | Select-Object -First 10) {
        Write-Warning "Password never expires: $($user.SamAccountName)"
    }
    
    # Check Domain Admins group
    Write-Info "Domain Admins members:"
    $domainAdmins = Get-ADGroupMember -Identity "Domain Admins" -ErrorAction SilentlyContinue
    foreach ($member in $domainAdmins) {
        Write-Alert "  $($member.SamAccountName) ($($member.objectClass))"
    }
    
    # Check Enterprise Admins group
    Write-Info "Enterprise Admins members:"
    $enterpriseAdmins = Get-ADGroupMember -Identity "Enterprise Admins" -ErrorAction SilentlyContinue
    foreach ($member in $enterpriseAdmins) {
        Write-Alert "  $($member.SamAccountName) ($($member.objectClass))"
    }
    
    # Check Schema Admins group
    Write-Info "Schema Admins members:"
    $schemaAdmins = Get-ADGroupMember -Identity "Schema Admins" -ErrorAction SilentlyContinue
    foreach ($member in $schemaAdmins) {
        Write-Alert "  $($member.SamAccountName) ($($member.objectClass))"
    }
    
    # Check for Kerberos delegation
    Write-Info "Checking for unconstrained Kerberos delegation..."
    $unconstrainedDelegation = Get-ADComputer -Filter {TrustedForDelegation -eq $true} -ErrorAction SilentlyContinue
    foreach ($computer in $unconstrainedDelegation) {
        Write-Alert "Unconstrained delegation: $($computer.Name)"
    }
    
    # Check for users with SPN (potential Kerberoasting targets)
    Write-Info "Checking for user accounts with SPNs..."
    $usersWithSPN = Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName -ErrorAction SilentlyContinue
    foreach ($user in $usersWithSPN) {
        Write-Warning "User with SPN (Kerberoastable): $($user.SamAccountName)"
    }
    
    # Check AdminSDHolder protected users
    Write-Info "Checking AdminCount attribute..."
    $adminCountUsers = Get-ADUser -Filter {AdminCount -eq 1} -ErrorAction SilentlyContinue
    Write-Info "Users with AdminCount=1: $($adminCountUsers.Count)"
    
    # Check default domain password policy
    Write-Info "Default Domain Password Policy:"
    $policy = Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue
    if ($policy) {
        Write-Info "  Min password length: $($policy.MinPasswordLength)"
        Write-Info "  Password history: $($policy.PasswordHistoryCount)"
        Write-Info "  Max password age: $($policy.MaxPasswordAge)"
        Write-Info "  Complexity enabled: $($policy.ComplexityEnabled)"
        Write-Info "  Lockout threshold: $($policy.LockoutThreshold)"
        Write-Info "  Lockout duration: $($policy.LockoutDuration)"
        
        # Warn on weak settings
        if ($policy.MinPasswordLength -lt 12) {
            Write-Alert "Weak password policy: Min length should be 12+"
        }
        if ($policy.LockoutThreshold -eq 0) {
            Write-Alert "Account lockout is disabled!"
        }
    }
}

# ============================================================
# LAPS CHECK (Local Administrator Password Solution)
# ============================================================

function Invoke-LAPSAudit {
    Write-Info "========== LAPS AUDIT =========="
    
    # Check if LAPS is installed
    $lapsInstalled = $false
    
    # Check for LAPS module
    if (Get-Module -ListAvailable -Name AdmPwd.PS -ErrorAction SilentlyContinue) {
        $lapsInstalled = $true
        Write-Success "LAPS PowerShell module is installed"
    }
    
    # Check for LAPS client
    $lapsClient = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*LAPS*" }
    if ($lapsClient) {
        $lapsInstalled = $true
        Write-Success "LAPS client is installed"
    }
    
    # Check for Windows LAPS (built into Server 2022/Windows 11)
    $windowsLaps = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config" -ErrorAction SilentlyContinue
    if ($windowsLaps) {
        $lapsInstalled = $true
        Write-Success "Windows LAPS is configured"
    }
    
    if (!$lapsInstalled) {
        Write-Warning "LAPS does not appear to be installed/configured"
        Write-Warning "Consider implementing LAPS for local admin password management"
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
                if ($line -match "google|microsoft|windows|update|security|antivirus|defender|bank|paypal") {
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
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"; Desc="HKLM RunServices"},
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce"; Desc="HKLM RunServicesOnce"}
    )
    
    foreach ($regPath in $startupPaths) {
        if (Test-Path $regPath.Path) {
            $items = Get-ItemProperty $regPath.Path -ErrorAction SilentlyContinue
            $props = $items.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }
            
            if ($props.Count -gt 0) {
                Write-Info "$($regPath.Desc):"
                foreach ($prop in $props) {
                    $isSuspicious = $false
                    $value = $prop.Value
                    
                    # Check for suspicious patterns
                    if ($value -match "temp|appdata\\local\\temp|downloads|public" -and $value -match "\.exe|\.bat|\.cmd|\.vbs|\.ps1") {
                        $isSuspicious = $true
                    }
                    if ($value -match "powershell.*(-enc|-encoded|downloadstring|iex|invoke|bypass|hidden|webclient)") {
                        $isSuspicious = $true
                    }
                    if ($value -match "wscript|cscript|mshta|rundll32.*javascript|regsvr32.*/s.*/u|certutil.*-decode") {
                        $isSuspicious = $true
                    }
                    if ($value -match "\\Users\\[^\\]+\\AppData\\") {
                        $isSuspicious = $true
                    }
                    
                    if ($isSuspicious) {
                        Write-Alert "  SUSPICIOUS: $($prop.Name) = $value"
                        Write-Host "      Remove this entry? (y/n): " -NoNewline -ForegroundColor Yellow
                        $response = Read-Host
                        if ($response -eq 'y') {
                            Remove-ItemProperty -Path $regPath.Path -Name $prop.Name -ErrorAction SilentlyContinue
                            Write-Success "Removed startup entry: $($prop.Name)"
                        }
                    } else {
                        Write-Info "  $($prop.Name) = $value"
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
                    if ($file.Extension -match "\.exe|\.bat|\.cmd|\.vbs|\.ps1|\.lnk|\.url") {
                        Write-Warning "  $($file.Name)"
                        
                        # If it's a shortcut, show target
                        if ($file.Extension -eq ".lnk") {
                            try {
                                $shell = New-Object -ComObject WScript.Shell
                                $shortcut = $shell.CreateShortcut($file.FullName)
                                Write-Warning "    Target: $($shortcut.TargetPath)"
                                
                                if ($shortcut.TargetPath -match "powershell|cmd|wscript|mshta") {
                                    Write-Alert "    SUSPICIOUS shortcut target!"
                                }
                            } catch {}
                        }
                    }
                }
            }
        }
    }
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
        if ($entry.Data -match "^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)" -and $entry.Entry -notmatch "local|internal|intranet") {
            Write-Alert "Suspicious DNS cache entry: $($entry.Entry) -> $($entry.Data)"
        }
    }
    
    # Clear DNS cache
    Write-Host "Clear DNS cache? (y/n): " -NoNewline -ForegroundColor Yellow
    $response = Read-Host
    if ($response -eq 'y') {
        Clear-DnsClientCache
        Write-Success "DNS cache cleared"
    }
}

# ============================================================
# ANSWER FILE CHECK (CyberPatriot specific)
# ============================================================

function Invoke-AnswerFileAudit {
    Write-Info "========== ANSWER FILE / UNATTEND AUDIT =========="
    
    # Check for unattend.xml files that may contain passwords
    $answerFilePaths = @(
        "C:\Windows\Panther\Unattend.xml",
        "C:\Windows\Panther\Unattend\Unattend.xml",
        "C:\Windows\Panther\unattend.xml",
        "C:\Windows\System32\sysprep\Unattend.xml",
        "C:\Windows\System32\sysprep\Panther\Unattend.xml",
        "C:\unattend.xml",
        "C:\autounattend.xml"
    )
    
    foreach ($path in $answerFilePaths) {
        if (Test-Path $path) {
            Write-Alert "Answer file found: $path"
            
            # Check for passwords in the file
            $content = Get-Content $path -Raw -ErrorAction SilentlyContinue
            if ($content -match "Password|Credential|AutoLogon") {
                Write-Alert "  File may contain sensitive information!"
            }
            
            Write-Host "    View file contents? (y/n): " -NoNewline -ForegroundColor Yellow
            $response = Read-Host
            if ($response -eq 'y') {
                Get-Content $path
            }
            
            Write-Host "    Delete this file? (y/n): " -NoNewline -ForegroundColor Yellow
            $response = Read-Host
            if ($response -eq 'y') {
                Remove-Item $path -Force -ErrorAction SilentlyContinue
                Write-Success "Deleted: $path"
            }
        }
    }
    
    # Check for sysprep logs
    $sysprepLogs = @(
        "C:\Windows\System32\sysprep\sysprep.inf",
        "C:\Windows\System32\sysprep\setupact.log",
        "C:\Windows\Panther\setupact.log"
    )
    
    foreach ($path in $sysprepLogs) {
        if (Test-Path $path) {
            Write-Warning "Sysprep file found: $path"
        }
    }
}

# ============================================================
# QUICK WINS
# ============================================================

function Invoke-QuickWins {
    Write-Info "========== QUICK WINS =========="
    
    # Rename Administrator account
    $currentAdmin = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
    if ($currentAdmin) {
        Write-Host "Rename Administrator account? (y/n): " -NoNewline -ForegroundColor Yellow
        $response = Read-Host
        if ($response -eq 'y') {
            Write-Host "    New name: " -NoNewline
            $newName = Read-Host
            if ($newName -and $newName -ne "Administrator") {
                Rename-LocalUser -Name "Administrator" -NewName $newName -ErrorAction SilentlyContinue
                Write-Success "Renamed Administrator to $newName"
            }
        }
    }
    
    # Rename Guest account
    $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if ($guest) {
        Rename-LocalUser -Name "Guest" -NewName "NoGuest" -ErrorAction SilentlyContinue
        Disable-LocalUser -Name "NoGuest" -ErrorAction SilentlyContinue
        Write-Success "Guest account renamed and disabled"
    }
    
    # Disable Guest account (in case rename failed)
    Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    
    # Enable DEP (Data Execution Prevention)
    bcdedit /set nx AlwaysOn 2>$null
    Write-Success "DEP set to AlwaysOn"
    
    # Enable SEHOP
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Write-Success "SEHOP enabled"
    
    # Disable IPv6 if not needed
    Write-Host "Disable IPv6? (y/n): " -NoNewline -ForegroundColor Yellow
    $response = Read-Host
    if ($response -eq 'y') {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Value 255 -Type DWord
        Write-Success "IPv6 disabled (requires restart)"
    }
    
    # Disable Sticky Keys backdoor
    $accessibilityPaths = @(
        "HKCU:\Control Panel\Accessibility\StickyKeys",
        "HKCU:\Control Panel\Accessibility\ToggleKeys",
        "HKCU:\Control Panel\Accessibility\Keyboard Response"
    )
    
    foreach ($path in $accessibilityPaths) {
        if (Test-Path $path) {
            Set-ItemProperty -Path $path -Name "Flags" -Value "506" -ErrorAction SilentlyContinue
        }
    }
    Write-Success "Accessibility shortcuts disabled (Sticky Keys backdoor prevention)"
    
    # Disable Windows Script Host
    Write-Host "Disable Windows Script Host? (y/n): " -NoNewline -ForegroundColor Yellow
    $response = Read-Host
    if ($response -eq 'y') {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Write-Success "Windows Script Host disabled"
    }
    
    # Disable Office macros (if Office is installed)
    $officePaths = @(
        "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Security",
        "HKCU:\SOFTWARE\Microsoft\Office\16.0\Excel\Security",
        "HKCU:\SOFTWARE\Microsoft\Office\16.0\PowerPoint\Security"
    )
    
    foreach ($path in $officePaths) {
        if (Test-Path $path) {
            Set-ItemProperty -Path $path -Name "VBAWarnings" -Value 4 -Type DWord -ErrorAction SilentlyContinue
            Write-Success "Office macro security: Disabled with notification"
        }
    }
    
    # Clear recent documents
    Remove-Item "$env:APPDATA\Microsoft\Windows\Recent\*" -Force -ErrorAction SilentlyContinue
    Write-Success "Recent documents cleared"
    
    # Clear temp files
    Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Success "Temp files cleared"
    
    # Flush DNS
    Clear-DnsClientCache
    Write-Success "DNS cache cleared"
    
    # Reset Windows Firewall
    Write-Host "Reset Windows Firewall to defaults? (y/n): " -NoNewline -ForegroundColor Yellow
    $response = Read-Host
    if ($response -eq 'y') {
        netsh advfirewall reset
        Write-Success "Windows Firewall reset to defaults"
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
            $xml = [xml]$_.ToXml()
            $user = $xml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" } | Select-Object -ExpandProperty '#text'
            $ip = $xml.Event.EventData.Data | Where-Object { $_.Name -eq "IpAddress" } | Select-Object -ExpandProperty '#text'
            Write-Warning "  $($_.TimeCreated): Failed logon - User: $user, IP: $ip"
        }
    
    Write-Info "Last 10 Successful Logons (Event 4624):"
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} -MaxEvents 10 -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -notmatch "SYSTEM|DWM-|UMFD-" } |
        ForEach-Object {
            $xml = [xml]$_.ToXml()
            $user = $xml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" } | Select-Object -ExpandProperty '#text'
            $logonType = $xml.Event.EventData.Data | Where-Object { $_.Name -eq "LogonType" } | Select-Object -ExpandProperty '#text'
            Write-Info "  $($_.TimeCreated): $user (Type: $logonType)"
        }
    
    Write-Info "Last 10 User Creations (Event 4720):"
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4720} -MaxEvents 10 -ErrorAction SilentlyContinue |
        ForEach-Object {
            $xml = [xml]$_.ToXml()
            $newUser = $xml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" } | Select-Object -ExpandProperty '#text'
            Write-Alert "  $($_.TimeCreated): User created: $newUser"
        }
    
    Write-Info "Last 10 Group Membership Changes (Event 4728/4732):"
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=@(4728,4732,4756)} -MaxEvents 10 -ErrorAction SilentlyContinue |
        ForEach-Object {
            $xml = [xml]$_.ToXml()
            $member = $xml.Event.EventData.Data | Where-Object { $_.Name -eq "MemberName" } | Select-Object -ExpandProperty '#text'
            $group = $xml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" } | Select-Object -ExpandProperty '#text'
            Write-Alert "  $($_.TimeCreated): $member added to $group"
        }
    
    Write-Info "Last 10 Process Creation Events (Event 4688):"
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} -MaxEvents 10 -ErrorAction SilentlyContinue |
        ForEach-Object {
            $xml = [xml]$_.ToXml()
            $process = $xml.Event.EventData.Data | Where-Object { $_.Name -eq "NewProcessName" } | Select-Object -ExpandProperty '#text'
            $cmdline = $xml.Event.EventData.Data | Where-Object { $_.Name -eq "CommandLine" } | Select-Object -ExpandProperty '#text'
            Write-Info "  $($_.TimeCreated): $process"
            if ($cmdline) { Write-Info "    Cmd: $cmdline" }
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
    Get-Process | Where-Object { $_.Path -and $_.Path -notmatch "Windows\\System32|Windows\\SysWOW64|Program Files" } |
        Select-Object Name, Path, Id | 
        Format-Table -AutoSize
    
    Write-Info "Recently Modified Executables (last 24 hours):"
    $recentFiles = Get-ChildItem -Path "C:\Users\*\Downloads", "C:\Users\*\Desktop", "C:\Windows\Temp", "C:\Temp", "C:\Users\*\AppData\Local\Temp" -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-24) -and $_.Extension -match "\.exe|\.bat|\.ps1|\.vbs|\.dll|\.cmd" }
    foreach ($file in $recentFiles | Select-Object -First 20) {
        Write-Warning "  $($file.LastWriteTime): $($file.FullName)"
    }
    
    Write-Info "Installed Software (last 7 days):"
    Get-WinEvent -FilterHashtable @{LogName='Application';Id=11707} -MaxEvents 20 -ErrorAction SilentlyContinue |
        Where-Object { $_.TimeCreated -gt (Get-Date).AddDays(-7) } |
        ForEach-Object {
            Write-Warning "  $($_.TimeCreated): $($_.Message.Substring(0, [Math]::Min(100, $_.Message.Length)))..."
        }
}

# ============================================================
# MAIN MENU
# ============================================================

function Show-Menu {
    Clear-Host
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "  CYBERPATRIOT SERVER 2022 HARDENING" -ForegroundColor Cyan
    Write-Host "         Complete Edition v3.0" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  OS: $OSCaption" -ForegroundColor Gray
    Write-Host "  DC: $IsDomainController | Server: $IsServer" -ForegroundColor Gray
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
    Write-Host "  [7]  SMB Hardening" -ForegroundColor Yellow
    Write-Host "  [8]  TLS/SSL Hardening" -ForegroundColor Yellow
    Write-Host "  [9]  Service Audit" -ForegroundColor Yellow
    Write-Host "  [10] Firewall Configuration" -ForegroundColor Yellow
    Write-Host "  [11] RDP Security" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  --- Malware & Software ---" -ForegroundColor Magenta
    Write-Host "  [12] Windows Defender" -ForegroundColor Yellow
    Write-Host "  [13] Windows Update" -ForegroundColor Yellow
    Write-Host "  [14] Prohibited Software Scan" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  --- Configuration Audit ---" -ForegroundColor Magenta
    Write-Host "  [15] Share Audit" -ForegroundColor Yellow
    Write-Host "  [16] Scheduled Task Audit" -ForegroundColor Yellow
    Write-Host "  [17] Features/Roles Audit" -ForegroundColor Yellow
    Write-Host "  [18] Hosts File Audit" -ForegroundColor Yellow
    Write-Host "  [19] Startup Programs Audit" -ForegroundColor Yellow
    Write-Host "  [20] DNS Settings Audit" -ForegroundColor Yellow
    Write-Host "  [21] Answer File Audit" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  --- Server Roles ---" -ForegroundColor Magenta
    Write-Host "  [22] IIS Hardening" -ForegroundColor Yellow
    Write-Host "  [23] Active Directory Audit" -ForegroundColor Yellow
    Write-Host "  [24] LAPS Audit" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  --- Tools ---" -ForegroundColor Magenta
    Write-Host "  [25] Quick Wins" -ForegroundColor Yellow
    Write-Host "  [26] Forensics Helper" -ForegroundColor Yellow
    Write-Host "  [27] System Info" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  [0]  Exit" -ForegroundColor Red
    Write-Host ""
}

function Invoke-AllHardening {
    Write-Info "Running complete hardening sequence..."
    Write-Info "=========================================="
    
    Show-SystemInfo
    Invoke-UserAudit
    Invoke-AdminAudit
    Set-PasswordPolicy
    Set-AuditPolicy
    Set-SecurityOptions
    Set-SMBSecurity
    Set-TLSSecurity
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
    Invoke-AnswerFileAudit
    Set-IISSecurity
    Invoke-ADSecurityAudit
    Invoke-LAPSAudit
    Invoke-QuickWins
    
    Write-Info "=========================================="
    Write-Info "HARDENING COMPLETE"
    Write-Info "Log saved to: $LogFile"
    Write-Info "=========================================="
    Write-Warning ""
    Write-Warning "MANUAL CHECKS STILL REQUIRED:"
    Write-Warning "  1. Review Local Security Policy (secpol.msc)"
    Write-Warning "  2. Check User Rights Assignment"
    Write-Warning "  3. Check Group Policy (gpedit.msc / gpmc.msc)"
    Write-Warning "  4. Review browser extensions manually"
    Write-Warning "  5. Check for hidden files/folders"
    Write-Warning "  6. Review README for any specific requirements"
    Write-Warning "  7. Answer Forensics Questions on desktop"
    Write-Warning "  8. Check Windows Firewall advanced rules"
    Write-Warning "  9. Review Certificate stores"
    Write-Warning " 10. Check Scheduled Tasks manually"
    Write-Warning ""
    Write-Warning "REBOOT RECOMMENDED to apply all changes"
    Write-Warning ""
}

# ============================================================
# MAIN EXECUTION
# ============================================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  CYBERPATRIOT SERVER 2022 HARDENING" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "  IMPORTANT: UPDATE CONFIGURATION FIRST!" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Before running, edit the script to set:" -ForegroundColor Yellow
Write-Host "    - `$AuthorizedUsers" -ForegroundColor White
Write-Host "    - `$AuthorizedAdmins" -ForegroundColor White
Write-Host "    - `$RequiredServices" -ForegroundColor White
Write-Host "    - `$RequiredPrograms" -ForegroundColor White
Write-Host "    - `$RequiredFeatures" -ForegroundColor White
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
        "7"  { Set-SMBSecurity }
        "8"  { Set-TLSSecurity }
        "9"  { Invoke-ServiceAudit }
        "10" { Set-FirewallConfiguration }
        "11" { Set-RDPSecurity }
        "12" { Set-DefenderConfiguration }
        "13" { Set-WindowsUpdate }
        "14" { Find-ProhibitedSoftware }
        "15" { Invoke-ShareAudit }
        "16" { Invoke-ScheduledTaskAudit }
        "17" { Invoke-FeatureAudit }
        "18" { Invoke-HostsFileAudit }
        "19" { Invoke-StartupAudit }
        "20" { Invoke-DNSAudit }
        "21" { Invoke-AnswerFileAudit }
        "22" { Set-IISSecurity }
        "23" { Invoke-ADSecurityAudit }
        "24" { Invoke-LAPSAudit }
        "25" { Invoke-QuickWins }
        "26" { Get-ForensicsInfo }
        "27" { Show-SystemInfo }
        "0"  { Write-Host "Exiting..."; break }
        default { Write-Host "Invalid option" -ForegroundColor Red }
    }
    
    if ($choice -ne "0") {
        Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
        Read-Host
    }
} while ($choice -ne "0")
