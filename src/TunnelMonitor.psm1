# TunnelMonitor.psm1 - Multi-Service SSH Tunnel Manager
# ========================================================================================================
# GENERAL-PURPOSE SSH TUNNEL MANAGER WITH MULTI-SERVICE HEALTH MONITORING
# Windows service integration, automatic recovery, and pluggable health checks
# Refactored from OllamaTunnelMonitor v1.7.0
# ========================================================================================================

#Requires -Version 7.1

# --------------------------------------------------------------------------------------------------------
# GLOBAL CONFIGURATION AND STATE
# --------------------------------------------------------------------------------------------------------

$script:TunnelMonitorConfig = @{
    # Target Configuration
    Target = @{
        LocalPort     = 11434
        RemoteHost    = "localhost"  
        RemotePort    = 11434
        SSHHost       = $env:POWERAUGER_LINUX_HOST -or $null
        SSHUser       = $env:POWERAUGER_SSH_USER -or $null
        SSHKey        = $env:POWERAUGER_SSH_KEY -or $null
        OllamaApiUrl  = "http://localhost:11434"
    }
    
    # Service Configuration
    Service = @{
        Name              = "TunnelMonitorService"
        Enabled           = $true
        StartupDelay      = 10        # seconds to wait after system startup
        MaxRetries        = 3
        RetryDelay        = 30        # seconds between retries
        HealthCheckInterval = 60      # seconds between health checks
    }
    
    # Monitoring Configuration
    Monitoring = @{
        Enabled           = $true
        IntervalSeconds   = 30
        HealthCheckCount  = 3
        TimeoutMs         = 5000
        RetryAttempts     = 3
        EnableLogging     = $true
        LogPath           = $null
        LogRetentionDays  = 7
    }
    
    # Model Discovery Configuration
    Models = @{
        DiscoveryEnabled     = $true
        DiscoveryInterval    = 300        # 5 minutes
        CacheExpiry          = 600        # 10 minutes
        AutoCategorize       = $true
        ExportToEnvironment  = $true
    }
    
    # Fast Status Configuration
    FastStatus = @{
        CacheTimeout      = 30           # seconds
        MaxResponseTime   = 100          # milliseconds target
    }

    # Additional Services Configuration (Multi-Port Forwarding)
    AdditionalServices = @{
        # ServiceName = @{LocalPort=X; RemotePort=Y; RemoteHost="localhost"}
        # OR simplified: ServiceName = Port (assumes same local/remote)
        # Example: VisionAPI = 5000
        # Example: Samba = @{LocalPort=445; RemotePort=445; RemoteHost="localhost"}
    }
}

# Global state containers
$script:TunnelProcess = $null
$script:TunnelMetrics = @{
    StartTime           = $null
    TotalChecks         = 0
    SuccessfulChecks    = 0
    FailedChecks        = 0
    AverageLatency      = 0
    LastCheckTime       = $null
    CurrentStatus       = "Unknown"
    StatusHistory       = @()
    Uptime              = [TimeSpan]::Zero
    RestartCount        = 0
}

$script:DiscoveredModels = @{
    AutoComplete = $null
    Coder = $null  
    Reranker = $null
    Embedding = $null
    Available = @()
    LastDiscovery = $null
}

$script:ServiceJob = $null
$script:IsServiceRunning = $false

# Mutex flags for preventing concurrent restart operations
$script:RestartInProgress = $false
$script:ServiceStopping = $false
$script:SSHTunnelExitEvent = $null

# --------------------------------------------------------------------------------------------------------
# DATA PERSISTENCE AND CONFIGURATION
# --------------------------------------------------------------------------------------------------------

# Determine data path based on context (SYSTEM vs User)
if ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -eq 'NT AUTHORITY\SYSTEM') {
    # Running as SYSTEM service - use ProgramData
    $script:TunnelMonitorDataPath = Join-Path -Path $env:ProgramData -ChildPath "TunnelMonitor"
} else {
    # Running as user - use user profile
    $script:TunnelMonitorDataPath = Join-Path -Path $env:USERPROFILE -ChildPath ".TunnelMonitor"
}
$script:TunnelMonitorConfigFile = Join-Path $script:TunnelMonitorDataPath "config.json"
$script:TunnelMonitorLogFile = Join-Path $script:TunnelMonitorDataPath "service.log"
$script:FastStatusFile = Join-Path $script:TunnelMonitorDataPath "fast_status.json"
$script:ModelsFile = Join-Path $script:TunnelMonitorDataPath "discovered_models.json"

# --------------------------------------------------------------------------------------------------------
# HELPER FUNCTIONS
# --------------------------------------------------------------------------------------------------------

function Initialize-DataPath {
    <#
    .SYNOPSIS
    Initialize the data directory and log path
    #>
    [CmdletBinding()]
    param()

    if (-not (Test-Path $script:TunnelMonitorDataPath)) {
        New-Item -Path $script:TunnelMonitorDataPath -ItemType Directory -Force | Out-Null
    }
    $script:TunnelMonitorConfig.Monitoring.LogPath = $script:TunnelMonitorLogFile
}

# --------------------------------------------------------------------------------------------------------
# ENVIRONMENT VARIABLE MANAGEMENT
# --------------------------------------------------------------------------------------------------------


#region Simple Environment Variable Functions
function Get-EnvVariable {
    param([string]$Name)

    # Check all scopes in order - Process first for overrides
    foreach ($scope in @('Process', 'User', 'Machine')) {
        $value = [Environment]::GetEnvironmentVariable($Name, $scope)
        if ($value) { return $value }
    }
    return $null
}

function Set-EnvVariable {
    param(
        [string]$Name,
        [string]$Value
    )

    # Always set Process for immediate availability
    [Environment]::SetEnvironmentVariable($Name, $Value, 'Process')

    # Don't persist SSH credentials
    if ($Name -in @('POWERAUGER_SSH_KEY', 'POWERAUGER_SSH_USER', 'POWERAUGER_LINUX_HOST')) {
        return  # Process-only for security
    }

    # Determine persistent scope based on privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    $scope = if ($isAdmin) { 'Machine' } else { 'User' }

    try {
        [Environment]::SetEnvironmentVariable($Name, $Value, $scope)
    } catch {
        # If Machine failed, try User
        if ($scope -eq 'Machine') {
            try {
                [Environment]::SetEnvironmentVariable($Name, $Value, 'User')
            } catch {
                Write-Warning "Could only set $Name in Process scope (not persistent)"
            }
        }
    }
}

function Remove-EnvVariable {
    param([string]$Name)

    # Remove from all scopes
    foreach ($scope in @('Process', 'User', 'Machine')) {
        try {
            [Environment]::SetEnvironmentVariable($Name, $null, $scope)
        } catch {
            # Ignore errors, just try to remove from all
        }
    }
}
#endregion

# Log buffer for improved performance
$script:LogBuffer = [System.Collections.ArrayList]::new()
$script:LastLogFlush = Get-Date

function Write-Log {
    [CmdletBinding()]
    param(
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error', 'Debug')]
        [string]$Level = 'Info',
        [switch]$Flush
    )

    if (-not $script:TunnelMonitorConfig.Monitoring.EnableLogging) { return }

    # Check for log rotation before writing
    if (Test-Path $script:TunnelMonitorConfig.Monitoring.LogPath) {
        $logFile = Get-Item $script:TunnelMonitorConfig.Monitoring.LogPath
        $maxSizeMB = 10  # Rotate at 10MB

        if ($logFile.Length -gt ($maxSizeMB * 1MB)) {
            try {
                # Rotate log file
                $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
                $archivePath = $logFile.FullName -replace '\.log$', "_$timestamp.log"
                Move-Item -Path $logFile.FullName -Destination $archivePath -Force

                # Clean up old logs (keep last 7 days worth)
                $logDir = Split-Path $logFile.FullName -Parent
                $oldLogs = Get-ChildItem -Path $logDir -Filter "*.log" |
                    Where-Object { $_.Name -match '_\d{8}_\d{6}\.log$' -and $_.LastWriteTime -lt (Get-Date).AddDays(-7) }
                $oldLogs | Remove-Item -Force
            }
            catch {
                # Rotation failed, continue logging anyway
            }
        }
    }

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] $Message"

    # Add to buffer
    $null = $script:LogBuffer.Add($logEntry)

    # Flush conditions: Explicit flush, error level, buffer size > 10, or time > 5 seconds
    $shouldFlush = $Flush -or
                   $Level -eq 'Error' -or
                   $script:LogBuffer.Count -gt 10 -or
                   ((Get-Date) - $script:LastLogFlush).TotalSeconds -gt 5

    if ($shouldFlush -and $script:LogBuffer.Count -gt 0) {
        try {
            # Write all buffered entries at once
            Add-Content -Path $script:TunnelMonitorConfig.Monitoring.LogPath -Value $script:LogBuffer -ErrorAction SilentlyContinue
            $script:LogBuffer.Clear()
            $script:LastLogFlush = Get-Date
        }
        catch {
            # Fail silently to prevent infinite loops
        }
    }

    # Console output for debugging (immediate, not buffered)
    if ($script:TunnelMonitorConfig.Monitoring.EnableDebug) {
        $color = switch ($Level) {
            'Error' { 'Red' }
            'Warning' { 'Yellow' }
            'Debug' { 'Gray' }
            default { 'White' }
        }
        Write-Host $logEntry -ForegroundColor $color
    }
}



# --------------------------------------------------------------------------------------------------------
# SSH TUNNEL MANAGEMENT
# --------------------------------------------------------------------------------------------------------

function Get-ExistingSSHTunnel {
    [CmdletBinding()]
    param()

    try {
        # Build list of all expected forwarded ports
        $expectedPorts = @($script:TunnelMonitorConfig.Target.LocalPort)

        foreach ($svcName in $script:TunnelMonitorConfig.AdditionalServices.Keys) {
            $expectedPorts += $script:TunnelMonitorConfig.AdditionalServices[$svcName].LocalPort
        }

        # Check for SSH processes with our specific tunnel configuration
        $sshProcesses = Get-Process -Name "ssh" -ErrorAction SilentlyContinue

        foreach ($process in $sshProcesses) {
            try {
                $commandLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($process.Id)" -ErrorAction SilentlyContinue).CommandLine

                # Check if command line contains ANY of our configured ports
                $foundPort = $false
                foreach ($port in $expectedPorts) {
                    if ($commandLine -like "*-L*${port}:*" -or $commandLine -like "*-L*:*:${port}*") {
                        $foundPort = $true
                        break
                    }
                }

                if ($foundPort) {
                    Write-Log "Found existing SSH tunnel (PID: $($process.Id))" -Level Debug
                    return @{
                        ProcessId = $process.Id
                        Process = $process
                        CommandLine = $commandLine
                        IsManaged = $true
                        StartTime = $process.StartTime
                    }
                }
            }
            catch { continue }
        }
        return $null
    }
    catch {
        Write-Log "Error checking for existing SSH tunnel: $($_.Exception.Message)" -Level Error
        return $null
    }
}

# --------------------------------------------------------------------------------------------------------
# SSH BINARY RESOLUTION
# --------------------------------------------------------------------------------------------------------

function Get-SSHExecutablePath {
    <#
    .SYNOPSIS
    Locate SSH executable with fallback paths for SYSTEM account

    .DESCRIPTION
    Searches standard Windows SSH locations since SYSTEM account has minimal PATH
    #>
    [CmdletBinding()]
    param()

    # Try standard Windows SSH locations
    $sshPaths = @(
        "C:\Windows\System32\OpenSSH\ssh.exe",
        "C:\Program Files\OpenSSH\ssh.exe",
        "${env:ProgramFiles}\OpenSSH\ssh.exe",
        "${env:ProgramFiles(x86)}\OpenSSH\ssh.exe",
        "C:\Program Files\Git\usr\bin\ssh.exe",
        "${env:ProgramFiles}\Git\usr\bin\ssh.exe"
    )

    foreach ($path in $sshPaths) {
        if (Test-Path $path) {
            Write-Log "Found SSH at: $path"
            return $path
        }
    }

    # Fallback to PATH search
    try {
        $sshCmd = Get-Command ssh -ErrorAction SilentlyContinue
        if ($sshCmd) {
            Write-Log "Found SSH via PATH: $($sshCmd.Source)"
            return $sshCmd.Source
        }
    }
    catch {
        Write-Log "Failed to search PATH for SSH: $($_.Exception.Message)" -Level Warning
    }

    # Last resort - check if ssh works without path
    try {
        $testResult = & ssh -V 2>&1
        if ($LASTEXITCODE -eq 0 -or $testResult -like "*OpenSSH*") {
            Write-Log "SSH works but path unknown, using 'ssh' directly" -Level Warning
            return "ssh"
        }
    }
    catch {
        Write-Log "SSH test failed: $($_.Exception.Message)" -Level Debug
    }

    Write-Log "SSH executable not found in any standard location" -Level Error
    throw "SSH executable not found. Please install OpenSSH client."
}

function Test-AdminPrivileges {
    <#
    .SYNOPSIS
    Check if current user has Administrator privileges

    .DESCRIPTION
    Returns true if the current PowerShell session is running with Administrator privileges

    .EXAMPLE
    if (Test-AdminPrivileges) { Write-Host "Running as admin" }
    #>
    [CmdletBinding()]
    param()

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-SSHKeyPermissions {
    [CmdletBinding()]
    param(
        [string]$KeyPath
    )

    if (-not (Test-Path $KeyPath)) {
        Write-Log "SSH key not found: $KeyPath" -Level Error
        return $false
    }

    # On Windows, check that the key is not world-readable
    try {
        $acl = Get-Acl $KeyPath
        $owner = $acl.Owner
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

        # Warning if key is not owned by current user
        if ($owner -ne $currentUser) {
            Write-Log "SSH key is not owned by current user ($owner vs $currentUser)" -Level Warning
        }

        # Check for excessive permissions
        $accessRules = $acl.Access | Where-Object { $_.IdentityReference -notlike "*\$env:USERNAME" -and $_.IdentityReference -notlike "BUILTIN\Administrators" }
        if ($accessRules) {
            Write-Log "SSH key has excessive permissions - accessible by: $($accessRules.IdentityReference -join ', ')" -Level Warning
            return $false
        }

        return $true
    }
    catch {
        Write-Log "Failed to check SSH key permissions: $($_.Exception.Message)" -Level Warning
        return $true  # Don't block on permission check failure
    }
}



function Start-ManagedSSHTunnel {
    [CmdletBinding()]
    param(
        [switch]$SilentFail  # Don't error if SSH fails, for service resilience
    )

    # Check for existing tunnel first
    $existingTunnel = Get-ExistingSSHTunnel
    if ($existingTunnel) {
        Write-Log "SSH tunnel already exists (PID: $($existingTunnel.ProcessId))"
        $script:TunnelProcess = $existingTunnel.Process
        # No PID tracking needed - service manages its own process
        return $existingTunnel
    }

    # Check if running as SYSTEM - use dedicated service keys
    $isSystem = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name -eq 'NT AUTHORITY\SYSTEM'

    if ($isSystem) {
        # Load service SSH configuration
        $serviceConfigPath = "C:\ProgramData\TunnelMonitor\keys\ssh_config.json"

        if (-not (Test-Path $serviceConfigPath)) {
            Write-Log "No service SSH configuration found. Use Set-TunnelConfiguration to configure SSH." -Level $(if ($SilentFail) { 'Warning' } else { 'Error' })
            if (-not $SilentFail) {
                Write-Log "Setup: Set-TunnelConfiguration -SSHHost <host> -SSHUser <user> -SSHKeyPath <key>" -Level Warning
            }
            return $null
        }

        try {
            $serviceConfig = Get-Content $serviceConfigPath -Raw | ConvertFrom-Json -AsHashtable

            # Verify private key exists and is readable by SYSTEM
            if (-not (Test-Path $serviceConfig.PrivateKeyPath)) {
                Write-Log "Service private key not found: $($serviceConfig.PrivateKeyPath)" -Level Error
                return $null
            }

            # Verify SYSTEM can actually read the key
            try {
                $keyContent = Get-Content $serviceConfig.PrivateKeyPath -ErrorAction Stop
                if ([string]::IsNullOrWhiteSpace($keyContent)) {
                    Write-Log "Service private key is empty" -Level Error
                    return $null
                }
                Write-Log "Successfully read service private key ($(([string]$keyContent -join '').Length) characters)"

                # Log ACL information for debugging
                try {
                    $acl = Get-Acl $serviceConfig.PrivateKeyPath
                    Write-Log "Key owner: $($acl.Owner)" -Level Debug
                    # Build permission string to avoid parser issues
                    $accessList = $acl.Access | ForEach-Object {
                        $identity = $_.IdentityReference
                        $rights = $_.FileSystemRights
                        "${identity}: ${rights}"
                    }
                    Write-Log "Key permissions: $($accessList -join '; ')" -Level Debug
                }
                catch {
                    Write-Log "Could not read key ACL: $($_.Exception.Message)" -Level Debug
                }
            }
            catch {
                Write-Log "Cannot read service private key: $($_.Exception.Message)" -Level Error
                Write-Log "Key path: $($serviceConfig.PrivateKeyPath)" -Level Error
                return $null
            }

            # Use service configuration for connection
            $sshHost = $serviceConfig.RemoteHost
            $sshUser = $serviceConfig.RemoteUser
            $localPort = $serviceConfig.LocalPort
            $remotePort = $serviceConfig.RemotePort
            $sshKeyPath = $serviceConfig.PrivateKeyPath

            Write-Log "Using dedicated service SSH keys from ProgramData"
        }
        catch {
            Write-Log "Failed to load service SSH configuration: $($_.Exception.Message)" -Level Error
            return $null
        }
    }
    else {
        # Running as user - use legacy configuration
        if (-not $script:TunnelMonitorConfig.Target.SSHHost -or
            -not $script:TunnelMonitorConfig.Target.SSHUser) {
            Write-Log "SSH configuration incomplete - Host: $($script:TunnelMonitorConfig.Target.SSHHost), User: $($script:TunnelMonitorConfig.Target.SSHUser)" -Level $(if ($SilentFail) { 'Warning' } else { 'Error' })
            return $null
        }

        $sshHost = $script:TunnelMonitorConfig.Target.SSHHost
        $sshUser = $script:TunnelMonitorConfig.Target.SSHUser
        $localPort = $script:TunnelMonitorConfig.Target.LocalPort
        $remotePort = $script:TunnelMonitorConfig.Target.RemotePort
        $sshKeyPath = $script:TunnelMonitorConfig.Target.SSHKey
    }

    # Sanitize SSH host and user inputs
    $cleanHost = $sshHost -replace '[^a-zA-Z0-9.-]', ''
    $cleanUser = $sshUser -replace '[^a-zA-Z0-9._-]', ''

    if ($cleanHost -ne $sshHost -or $cleanUser -ne $sshUser) {
        Write-Log "SSH configuration contains invalid characters" -Level Error
        return $null
    }

    try {
        # Build SSH arguments with proper escaping
        $localPortNum = [int]$localPort
        $remotePortNum = [int]$remotePort

        $sshArgs = @(
            "-N"  # No remote command execution
            "-L", "${localPortNum}:localhost:${remotePortNum}"
        )

        # Add additional services (multi-port forwarding)
        if ($script:TunnelMonitorConfig.AdditionalServices.Count -gt 0) {
            Write-Log "Configuring $($script:TunnelMonitorConfig.AdditionalServices.Count) additional service(s) for forwarding"
            foreach ($serviceName in $script:TunnelMonitorConfig.AdditionalServices.Keys) {
                $svc = $script:TunnelMonitorConfig.AdditionalServices[$serviceName]

                # Build port mapping string to avoid parser issues with colons after subexpressions
                $localP = $svc.LocalPort
                $remoteH = $svc.RemoteHost
                $remoteP = $svc.RemotePort
                $portMapping = "${localP}:${remoteH}:${remoteP}"

                $sshArgs += "-L"
                $sshArgs += $portMapping
                Write-Log "  - ${serviceName}: $localP -> ${remoteH}:${remoteP}"
            }
        }

        # Add SSH options
        $sshArgs += @(
            "-o", "TCPKeepAlive=yes"  # Enable TCP-level keepalives
            "-o", "ServerAliveInterval=30"  # Reduced from 60 for faster detection
            "-o", "ServerAliveCountMax=3"
            "-o", "ExitOnForwardFailure=no"  # Don't exit on temporary failures
            "-o", "StrictHostKeyChecking=no"
            "-o", "UserKnownHostsFile=NUL"  # Windows-compatible null device
            "-o", "LogLevel=ERROR"  # Capture errors
            "-o", "ConnectTimeout=10"  # Reduced from 30 for faster recovery
            "-o", "ConnectionAttempts=3"  # Retry connection on failure
            "-o", "BatchMode=yes"  # Non-interactive mode
            "-o", "PasswordAuthentication=no"  # Force key-only auth
        )

        # Add SSH key if available
        if ($sshKeyPath -and (Test-Path $sshKeyPath)) {
            if ($isSystem -or (Test-SSHKeyPermissions -KeyPath $sshKeyPath)) {
                $sshArgs += @("-i", $sshKeyPath)
                Write-Log "Using SSH key: $sshKeyPath"
            } else {
                Write-Log "SSH key failed security validation" -Level Warning
            }
        } elseif ($sshKeyPath) {
            Write-Log "SSH key not found: $sshKeyPath" -Level Warning
        }

        # Add target with sanitized values
        $sshArgs += "${cleanUser}@${cleanHost}"
        
        Write-Log "Starting SSH tunnel: ssh $($sshArgs -join ' ')"

        # Get SSH executable path
        try {
            $sshPath = Get-SSHExecutablePath
        }
        catch {
            Write-Log "Failed to locate SSH: $($_.Exception.Message)" -Level Error
            if ($SilentFail) {
                return $null
            }
            throw
        }

        # Prepare to capture SSH output for debugging
        $tempOut = Join-Path $env:TEMP "ssh_tunnel_out_$(Get-Date -Format 'yyyyMMddHHmmss').txt"
        $tempErr = Join-Path $env:TEMP "ssh_tunnel_err_$(Get-Date -Format 'yyyyMMddHHmmss').txt"

        # Start SSH process with output capture
        $processInfo = Start-Process -FilePath $sshPath -ArgumentList $sshArgs `
            -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput $tempOut `
            -RedirectStandardError $tempErr `
            -ErrorAction Stop
        
        # Wait briefly for tunnel to establish
        Start-Sleep -Seconds 3
        
        # Verify process is still running
        if ($processInfo.HasExited) {
            $logLevel = if ($SilentFail) { 'Warning' } else { 'Error' }

            # Capture and log SSH output for debugging
            $errorOutput = if (Test-Path $tempErr) { Get-Content $tempErr -Raw } else { "No error output" }
            $standardOutput = if (Test-Path $tempOut) { Get-Content $tempOut -Raw } else { "No standard output" }

            Write-Log "SSH tunnel process exited immediately (Exit code: $($processInfo.ExitCode))" -Level $logLevel
            if ($errorOutput -and $errorOutput -ne "No error output") {
                Write-Log "SSH Error Output: $errorOutput" -Level $logLevel
            }
            if ($standardOutput -and $standardOutput -ne "No standard output") {
                Write-Log "SSH Standard Output: $standardOutput" -Level Debug
            }

            # Clean up temp files
            Remove-Item $tempOut, $tempErr -ErrorAction SilentlyContinue

            if ($SilentFail) {
                Write-Log "Service will continue without tunnel - status APIs remain available" -Level Warning
            }
            return $null
        }

        # Clean up temp files after successful start
        Start-Sleep -Seconds 1
        Remove-Item $tempOut, $tempErr -ErrorAction SilentlyContinue
        
        # Track process globally
        $script:TunnelProcess = $processInfo
        $script:TunnelMetrics.RestartCount++

        # Register process exit event for instant crash detection
        try {
            # Clean up any existing event registration
            if ($script:SSHTunnelExitEvent) {
                Unregister-Event -SourceIdentifier $script:SSHTunnelExitEvent.Name -ErrorAction SilentlyContinue
                $script:SSHTunnelExitEvent = $null
            }

            # Enable event raising on the process
            $processInfo.EnableRaisingEvents = $true

            # Register the exit event handler
            $script:SSHTunnelExitEvent = Register-ObjectEvent -InputObject $processInfo -EventName Exited -Action {
                $exitCode = $Event.SourceObject.ExitCode
                $pid = $Event.SourceObject.Id

                # Check if this is an intentional stop or a restart is already in progress
                if (-not $script:ServiceStopping -and -not $script:RestartInProgress) {
                    $script:RestartInProgress = $true
                    Write-Log "SSH tunnel process $pid exited unexpectedly with code $exitCode" -Level Error

                    # Brief delay to prevent rapid restart loops
                    Start-Sleep -Seconds 5

                    try {
                        # Check if service is still running before attempting restart
                        $task = Get-ScheduledTask -TaskName 'TunnelMonitorService' -ErrorAction SilentlyContinue
                        if ($task -and $task.State -eq 'Running') {
                            Write-Log "Attempting automatic restart of SSH tunnel via exit event" -Level Warning
                            $result = Start-ManagedSSHTunnel -SilentFail
                            if ($result) {
                                Write-Log "SSH tunnel restarted successfully via exit event"
                            } else {
                                Write-Log "Failed to restart SSH tunnel via exit event" -Level Error
                            }
                        }
                    }
                    catch {
                        Write-Log "Error during automatic SSH tunnel restart: $_" -Level Error
                    }
                    finally {
                        $script:RestartInProgress = $false
                    }
                }
            }

            Write-Log "Process exit event handler registered for PID $($processInfo.Id)" -Level Debug
        }
        catch {
            Write-Log "Failed to register process exit event: $_" -Level Warning
            # Continue anyway - polling will still work as backup
        }

        # No PID tracking needed - service manages its own process

        Write-Log "SSH tunnel started successfully (PID: $($processInfo.Id))"
        
        return @{
            ProcessId = $processInfo.Id
            Process = $processInfo
            IsManaged = $true
            StartTime = Get-Date
        }
    }
    catch {
        $logLevel = if ($SilentFail) { 'Warning' } else { 'Error' }
        Write-Log "Failed to start SSH tunnel: $($_.Exception.Message)" -Level $logLevel

        if ($SilentFail) {
            Write-Log "Service continuing without tunnel - monitoring and status features remain available" -Level Warning
        }
        return $null
    }
}

function Stop-ManagedSSHTunnel {
    [CmdletBinding()]
    param(
        [switch]$Force
    )

    try {
        # Set flag to prevent exit event handler from restarting during intentional stop
        $script:ServiceStopping = $true

        # Clean up event registration
        if ($script:SSHTunnelExitEvent) {
            try {
                Unregister-Event -SourceIdentifier $script:SSHTunnelExitEvent.Name -ErrorAction SilentlyContinue
                $script:SSHTunnelExitEvent = $null
                Write-Log "Process exit event handler unregistered" -Level Debug
            }
            catch {
                Write-Log "Failed to unregister process exit event: $_" -Level Debug
            }
        }

        if ($script:TunnelProcess -and -not $script:TunnelProcess.HasExited) {
            Write-Log "Stopping managed SSH tunnel (PID: $($script:TunnelProcess.Id))"

            if ($Force) {
                $script:TunnelProcess.Kill()
            }
            else {
                $script:TunnelProcess.CloseMainWindow()
                if (-not $script:TunnelProcess.WaitForExit(5000)) {
                    $script:TunnelProcess.Kill()
                }
            }
            Write-Log "SSH tunnel stopped"
        }

        # Clean up any orphaned SSH processes
        $orphanedTunnels = Get-ExistingSSHTunnel
        if ($orphanedTunnels) {
            Write-Log "Cleaning up orphaned SSH tunnel (PID: $($orphanedTunnels.ProcessId))"
            Stop-Process -Id $orphanedTunnels.ProcessId -Force -ErrorAction SilentlyContinue
        }

        $script:TunnelProcess = $null

        # No PID tracking needed
    }
    catch {
        Write-Log "Error stopping SSH tunnel: $($_.Exception.Message)" -Level Error
    }
    finally {
        # Reset flag after stop completes
        $script:ServiceStopping = $false
    }
}

# --------------------------------------------------------------------------------------------------------
# MODEL DISCOVERY AND CATEGORIZATION ENGINE
# --------------------------------------------------------------------------------------------------------

function Get-OllamaModels {
    [CmdletBinding()]
    param(
        [switch]$Force
    )
    
    # Check cache validity
    if (-not $Force -and $script:DiscoveredModels.LastDiscovery) {
        $cacheAge = (Get-Date) - $script:DiscoveredModels.LastDiscovery
        if ($cacheAge.TotalSeconds -lt $script:TunnelMonitorConfig.Models.CacheExpiry) {
            Write-Log "Using cached model discovery (age: $([math]::Round($cacheAge.TotalMinutes, 1)) minutes)"
            return $script:DiscoveredModels
        }
    }
    
    try {
        Write-Log "Getting Ollama models..."
        $modelsResponse = Invoke-RestMethod -Uri "$($script:TunnelMonitorConfig.Target.OllamaApiUrl)/api/tags" -TimeoutSec 10 -ErrorAction Stop
        $models = $modelsResponse.models
        
        if (-not $models) {
            Write-Log "No models found on Ollama server" -Level Warning
            return $script:DiscoveredModels
        }
        
        # Reset categorized models
        $script:DiscoveredModels = @{
            AutoComplete = $null
            Coder = $null
            Reranker = $null
            Embedding = $null
            Available = @()
            LastDiscovery = Get-Date
        }
        
        foreach ($model in $models) {
            $modelName = $model.name
            $script:DiscoveredModels.Available += $modelName
            
            Write-Log "Found model: $modelName" -Level Debug
            
            # Simple categorization: Look for keywords in model names
            # Prioritize -custom models over non-custom ones
            $lowerName = $modelName.ToLower()
            $isCustom = $lowerName -match 'custom'

            # AutoComplete model (prefer custom)
            if ($lowerName -match 'autocomplete') {
                if (-not $script:DiscoveredModels.AutoComplete -or
                    ($isCustom -and $script:DiscoveredModels.AutoComplete -notmatch 'custom')) {
                    $script:DiscoveredModels.AutoComplete = $modelName
                    Write-Log "Categorized as AutoComplete: $modelName"
                }
            }

            # Coder model (prefer custom)
            if ($lowerName -match 'coder|code') {
                if (-not $script:DiscoveredModels.Coder -or
                    ($isCustom -and $script:DiscoveredModels.Coder -notmatch 'custom')) {
                    $script:DiscoveredModels.Coder = $modelName
                    Write-Log "Categorized as Coder: $modelName"
                }
            }

            # Reranker model (prefer custom)
            if ($lowerName -match 'rerank') {
                if (-not $script:DiscoveredModels.Reranker -or
                    ($isCustom -and $script:DiscoveredModels.Reranker -notmatch 'custom')) {
                    $script:DiscoveredModels.Reranker = $modelName
                    Write-Log "Categorized as Reranker: $modelName"
                }
            }

            # Embedding model (prefer custom)
            if ($lowerName -match 'embed') {
                if (-not $script:DiscoveredModels.Embedding -or
                    ($isCustom -and $script:DiscoveredModels.Embedding -notmatch 'custom')) {
                    $script:DiscoveredModels.Embedding = $modelName
                    Write-Log "Categorized as Embedding: $modelName"
                }
            }
        }
        
        # Fallback selection for missing categories
        if (-not $script:DiscoveredModels.AutoComplete -and $script:DiscoveredModels.Available) {
            # Select smallest available model for autocomplete
            $sortedModels = $script:DiscoveredModels.Available | Sort-Object { 
                # Extract size indicators and prioritize smaller models
                if ($_ -match '(\d+\.?\d*)b') { [double]$matches[1] } else { 999 }
            }
            $script:DiscoveredModels.AutoComplete = $sortedModels[0]
            Write-Log "Using fallback AutoComplete model: $($script:DiscoveredModels.AutoComplete)"
        }
        
        if (-not $script:DiscoveredModels.Coder -and $script:DiscoveredModels.Available) {
            # Select most capable model for coding (prefer larger models with 'code' in name)
            $codingCandidates = $script:DiscoveredModels.Available | Where-Object { $_ -like "*code*" -or $_ -like "*coder*" }
            if ($codingCandidates) {
                $script:DiscoveredModels.Coder = ($codingCandidates | Sort-Object { 
                    if ($_ -match '(\d+\.?\d*)b') { -[double]$matches[1] } else { 0 }
                })[0]
            }
            else {
                # Use largest available model as fallback
                $script:DiscoveredModels.Coder = ($script:DiscoveredModels.Available | Sort-Object)[-1]
            }
            Write-Log "Using fallback Coder model: $($script:DiscoveredModels.Coder)"
        }
        
        # Save discovered models to cache file
        try {
            $script:DiscoveredModels | ConvertTo-Json -Depth 5 | Set-Content $script:ModelsFile -Encoding UTF8
        }
        catch {
            Write-Log "Failed to cache discovered models: $($_.Exception.Message)" -Level Warning
        }
        
        Write-Log "Model discovery completed - Found $($script:DiscoveredModels.Available.Count) models"
        
        # Export to environment variables if enabled
        if ($script:TunnelMonitorConfig.Models.ExportToEnvironment) {
            Export-ModelEnvironmentVariables -CategorizedModels $script:DiscoveredModels
        }
        
        return $script:DiscoveredModels
        
    }
    catch {
        Write-Log "Failed to discover models: $($_.Exception.Message)" -Level Error
        
        # Try to load from cache file as fallback
        if (Test-Path $script:ModelsFile) {
            try {
                $cachedModels = Get-Content $script:ModelsFile -Raw | ConvertFrom-Json -AsHashtable
                Write-Log "Using cached models from file as fallback"
                return $cachedModels
            }
            catch {
                Write-Log "Failed to load cached models: $($_.Exception.Message)" -Level Warning
            }
        }
        
        return $script:DiscoveredModels
    }
}

function Get-RemoteGPUStatus {
    $config = Get-TunnelConfiguration
    if (-not $config.SSHHost) {
        Write-Error "No tunnel configuration found"
        return
    }

    $sshArgs = @(
        "-i", $config.SSHKeyPath,
        "$($config.SSHUser)@$($config.SSHHost)",
        "nvidia-smi --query-gpu=name,memory.used,memory.total,utilization.gpu,temperature.gpu --format=csv"
    )

    $result = & ssh $sshArgs 2>$null
    $result | ConvertFrom-Csv
}

function Export-ModelEnvironmentVariables {
    [CmdletBinding()]
    param(
        [hashtable]$CategorizedModels,
        [switch]$UserScope  # Ignored - scope auto-detected in Set-EnvVariable
    )

    # Sanitize model names to prevent injection
    function Get-SanitizedModelName {
        param([string]$ModelName)
        if ([string]::IsNullOrEmpty($ModelName)) { return $null }
        # Remove any characters that could be problematic in environment variables
        return $ModelName -replace '[^a-zA-Z0-9.:_-]', '_'
    }

    $envVars = @{
        'OLLAMA_AUTOCOMPLETE_MODEL' = Get-SanitizedModelName $CategorizedModels.AutoComplete
        'OLLAMA_CODER_MODEL' = Get-SanitizedModelName $CategorizedModels.Coder
        'OLLAMA_RERANKER_MODEL' = Get-SanitizedModelName $CategorizedModels.Reranker
        'OLLAMA_EMBEDDING_MODEL' = Get-SanitizedModelName $CategorizedModels.Embedding
        'OLLAMA_TUNNEL_STATUS' = 'MANAGED'
        'OLLAMA_API_URL' = $script:TunnelMonitorConfig.Target.OllamaApiUrl
        'OLLAMA_MODEL_COUNT' = [int]$CategorizedModels.Available.Count
    }

    foreach ($envVar in $envVars.GetEnumerator()) {
        if ($null -ne $envVar.Value) {
            Set-EnvVariable -Name $envVar.Key -Value $envVar.Value.ToString()
            Write-Log "Set environment variable: $($envVar.Key) = $($envVar.Value)" -Level Debug
        }
    }

    Write-Log "Model environment variables exported successfully"
}

# --------------------------------------------------------------------------------------------------------
# UNIFIED STATUS AND CONFIGURATION FUNCTIONS
# --------------------------------------------------------------------------------------------------------

function Test-TCPPort {
    <#
    .SYNOPSIS
    Test TCP connectivity to a local port

    .DESCRIPTION
    Internal helper function to test if a TCP port is listening

    .PARAMETER Port
    The port number to test

    .PARAMETER Timeout
    Timeout in milliseconds (default 2000)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$Port,

        [int]$Timeout = 2000
    )

    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $connect = $tcpClient.BeginConnect("localhost", $Port, $null, $null)
        $portStatus = $connect.AsyncWaitHandle.WaitOne($Timeout, $false)
        if ($portStatus) { $tcpClient.EndConnect($connect) }
        $tcpClient.Close()
        return $portStatus
    }
    catch {
        return $false
    }
}

function Test-TunnelPorts {
    <#
    .SYNOPSIS
    Test connectivity to all forwarded tunnel ports

    .DESCRIPTION
    Performs quick TCP connectivity checks on main service and all additional services.
    Does NOT perform HTTP/application-level checks - just port listening status.

    .EXAMPLE
    Test-TunnelPorts

    .EXAMPLE
    Test-TunnelPorts | Where-Object {-not $_.Listening}  # Show only failed ports
    #>
    [CmdletBinding()]
    param()

    $results = @()

    # Test main service
    $mainPort = $script:TunnelMonitorConfig.Target.LocalPort
    $start = Get-Date
    $listening = Test-TCPPort -Port $mainPort
    $responseTime = if ($listening) {
        [math]::Round(((Get-Date) - $start).TotalMilliseconds, 1)
    } else {
        -1
    }

    $results += [PSCustomObject]@{
        ServiceName = "Main"
        Port = $mainPort
        Listening = $listening
        ResponseTimeMs = $responseTime
    }

    # Test additional services
    foreach ($serviceName in $script:TunnelMonitorConfig.AdditionalServices.Keys) {
        $svc = $script:TunnelMonitorConfig.AdditionalServices[$serviceName]
        $start = Get-Date
        $listening = Test-TCPPort -Port $svc.LocalPort
        $responseTime = if ($listening) {
            [math]::Round(((Get-Date) - $start).TotalMilliseconds, 1)
        } else {
            -1
        }

        $results += [PSCustomObject]@{
            ServiceName = $serviceName
            Port = $svc.LocalPort
            Listening = $listening
            ResponseTimeMs = $responseTime
        }
    }

    return $results
}

function Get-TunnelStatus {
    <#
    .SYNOPSIS
    Get the status of the tunnel service and Ollama API

    .DESCRIPTION
    Provides comprehensive status of the tunnel service, including service state,
    API responsiveness, model count, and response time metrics.

    .PARAMETER Check
    Level of status check to perform:
    - Quick: Only check service status (fastest)
    - Service: Check service and basic API connectivity
    - Full: Complete check including model count (default)

    .EXAMPLE
    Get-TunnelStatus

    .EXAMPLE
    Get-TunnelStatus -Check Quick
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('Quick', 'Service', 'Full')]
        [string]$Check = 'Full'
    )

    $status = [PSCustomObject]@{
        ServiceInstalled = $false
        ServiceRunning = $false
        TunnelProcessAlive = $false
        PortListening = $false
        APIResponding = $false
        ModelCount = 0
        ResponseTimeMs = -1
        Status = "Unknown"
        AdditionalServices = @()
        Timestamp = Get-Date
    }

    # Check port connectivity first (doesn't require admin)
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $connect = $tcpClient.BeginConnect("localhost", $script:TunnelMonitorConfig.Target.LocalPort, $null, $null)
        $portStatus = $connect.AsyncWaitHandle.WaitOne(2000, $false)
        if ($portStatus) { $tcpClient.EndConnect($connect) }
        $tcpClient.Close()
        $status.PortListening = $true
    } catch {
        $status.PortListening = $false
    }

    # Check API if port is open
    if ($Check -in 'Service', 'Full' -and $status.PortListening) {
        try {
            $start = Get-Date

            if ($Check -eq 'Full') {
                # Full check including model count
                $api = Invoke-RestMethod "http://localhost:11434/api/tags" -TimeoutSec 2
                $status.APIResponding = $true
                $status.ModelCount = @($api.models).Count
            }
            else {
                # Quick API ping only
                $null = Invoke-RestMethod "http://localhost:11434/api/version" -TimeoutSec 1
                $status.APIResponding = $true
            }

            $status.ResponseTimeMs = [math]::Round(((Get-Date) - $start).TotalMilliseconds, 1)
        }
        catch {
            # API not responding, leave defaults
        }
    }

    # Check service - requires admin to see SYSTEM tasks
    try {
        $task = Get-ScheduledTask -TaskName 'TunnelMonitorService' -ErrorAction SilentlyContinue
        $status.ServiceInstalled = ($null -ne $task)
        if ($task) {
            $status.ServiceRunning = ($task.State -eq 'Running')
        }
    }
    catch {
        # If we can't check the task, infer from other indicators
        Write-Log "Cannot query scheduled task (may need admin privileges)" -Level Debug
    }

    # Check tunnel process - check both script variable and actual processes
    if ($script:TunnelProcess -and -not $script:TunnelProcess.HasExited) {
        $status.TunnelProcessAlive = $true
    }
    else {
        # Also check for any SSH tunnel process on our port
        $existingTunnel = Get-ExistingSSHTunnel
        if ($existingTunnel) {
            $status.TunnelProcessAlive = $true
            # If we found a tunnel but couldn't see the service, likely permission issue
            if (-not $status.ServiceInstalled) {
                $status.ServiceInstalled = $true  # Inferred
                $status.ServiceRunning = $true    # Inferred
                Write-Log "Service status inferred from running tunnel (admin required for direct check)" -Level Debug
            }
        }
        elseif ($status.PortListening -and $status.APIResponding) {
            # Port is listening and API responds but we can't see the process
            # This typically means a SYSTEM-owned SSH process we can't inspect
            # Check if ANY ssh.exe process exists
            $sshProcesses = Get-Process -Name "ssh" -ErrorAction SilentlyContinue
            if ($sshProcesses) {
                $status.TunnelProcessAlive = $true
                $status.ServiceInstalled = $true  # Inferred from working API + SSH process
                $status.ServiceRunning = $true    # Inferred
                Write-Log "Service inferred from API response + SSH process (SYSTEM process not visible to user)" -Level Debug
            }
        }
    }

    # Check additional services (if not Quick mode)
    if ($Check -ne 'Quick' -and $script:TunnelMonitorConfig.AdditionalServices.Count -gt 0) {
        foreach ($serviceName in $script:TunnelMonitorConfig.AdditionalServices.Keys) {
            $svc = $script:TunnelMonitorConfig.AdditionalServices[$serviceName]

            $svcStatus = [PSCustomObject]@{
                Name = $serviceName
                Port = $svc.LocalPort
                Listening = (Test-TCPPort -Port $svc.LocalPort)
            }

            $status.AdditionalServices += $svcStatus
        }
    }

    # Determine overall status
    # If any additional service is down, mark as Partial
    $additionalServicesDown = $status.AdditionalServices | Where-Object {-not $_.Listening}

    $status.Status = if ($status.APIResponding -and $status.PortListening -and -not $additionalServicesDown) { "Operational" }
                    elseif (($status.PortListening -or $status.APIResponding) -and $additionalServicesDown) { "Partial" }
                    elseif ($status.PortListening) { "Partial" }
                    elseif ($status.TunnelProcessAlive) { "Connecting" }
                    elseif ($status.ServiceRunning) { "Starting" }
                    elseif ($status.ServiceInstalled) { "Stopped" }
                    else { "Not Installed" }

    return $status
}


function Set-TunnelConfiguration {
    <#
    .SYNOPSIS
    Configure SSH tunnel settings

    .DESCRIPTION
    Configure SSH tunnel with optional multi-service port forwarding.

    .PARAMETER AdditionalServices
    Hashtable of additional services to forward. Key = ServiceName, Value = Port or @{LocalPort=X; RemotePort=Y}

    .EXAMPLE
    Set-TunnelConfiguration -SSHHost "server" -SSHUser "user" -AdditionalServices @{VisionAPI=5000; Samba=445}
    #>
    [CmdletBinding()]
    param(
        [string]$SSHHost,
        [string]$SSHUser,
        [string]$SSHKeyPath,
        [int]$LocalPort = 11434,
        [int]$RemotePort = 11434,
        [hashtable]$AdditionalServices
    )

    # Update configuration
    if ($PSBoundParameters.ContainsKey('SSHHost')) {
        $script:TunnelMonitorConfig.Target.SSHHost = $SSHHost
    }
    if ($PSBoundParameters.ContainsKey('SSHUser')) {
        $script:TunnelMonitorConfig.Target.SSHUser = $SSHUser
    }
    if ($PSBoundParameters.ContainsKey('SSHKeyPath')) {
        $script:TunnelMonitorConfig.Target.SSHKey = $SSHKeyPath
    }
    if ($PSBoundParameters.ContainsKey('LocalPort')) {
        $script:TunnelMonitorConfig.Target.LocalPort = $LocalPort
    }
    if ($PSBoundParameters.ContainsKey('RemotePort')) {
        $script:TunnelMonitorConfig.Target.RemotePort = $RemotePort
    }

    # Handle additional services
    if ($PSBoundParameters.ContainsKey('AdditionalServices')) {
        $script:TunnelMonitorConfig.AdditionalServices = @{}

        foreach ($serviceName in $AdditionalServices.Keys) {
            $serviceConfig = $AdditionalServices[$serviceName]

            if ($serviceConfig -is [int]) {
                # Simplified: ServiceName = Port (same local/remote)
                $script:TunnelMonitorConfig.AdditionalServices[$serviceName] = @{
                    LocalPort = $serviceConfig
                    RemotePort = $serviceConfig
                    RemoteHost = "localhost"
                }
                Write-Verbose "Added service '$serviceName' forwarding port $serviceConfig"
            }
            elseif ($serviceConfig -is [hashtable]) {
                # Full config: ServiceName = @{LocalPort=X; RemotePort=Y; RemoteHost=Z}
                $localPort = $serviceConfig.LocalPort
                $remotePort = if ($serviceConfig.ContainsKey('RemotePort')) { $serviceConfig.RemotePort } else { $localPort }
                $remoteHost = if ($serviceConfig.ContainsKey('RemoteHost')) { $serviceConfig.RemoteHost } else { "localhost" }

                $script:TunnelMonitorConfig.AdditionalServices[$serviceName] = @{
                    LocalPort = $localPort
                    RemotePort = $remotePort
                    RemoteHost = $remoteHost
                }
                Write-Verbose "Added service '$serviceName' forwarding $localPort -> ${remoteHost}:${remotePort}"
            }
            else {
                Write-Warning "Invalid configuration for service '$serviceName' - must be int or hashtable"
            }
        }
    }

    # Save to file
    Initialize-DataPath
    $script:TunnelMonitorConfig | ConvertTo-Json -Depth 10 | Set-Content -Path $script:TunnelMonitorConfigFile -Encoding UTF8

    if ($script:TunnelMonitorConfig.AdditionalServices.Count -gt 0) {
        Write-Host "Configuration updated successfully with $($script:TunnelMonitorConfig.AdditionalServices.Count) additional service(s)" -ForegroundColor Green
    }
    else {
        Write-Host "Configuration updated successfully" -ForegroundColor Green
    }

    return $script:TunnelMonitorConfig.Target
}

function Get-TunnelConfiguration {
    <#
    .SYNOPSIS
    Get current tunnel configuration
    #>
    [CmdletBinding()]
    param()

    return [PSCustomObject]@{
        SSHHost = $script:TunnelMonitorConfig.Target.SSHHost
        SSHUser = $script:TunnelMonitorConfig.Target.SSHUser
        SSHKeyPath = $script:TunnelMonitorConfig.Target.SSHKey
        LocalPort = $script:TunnelMonitorConfig.Target.LocalPort
        RemotePort = $script:TunnelMonitorConfig.Target.RemotePort
        APIUrl = $script:TunnelMonitorConfig.Target.OllamaApiUrl
        AdditionalServices = $script:TunnelMonitorConfig.AdditionalServices
    }
}


# --------------------------------------------------------------------------------------------------------
# FAST STATUS API FOR POWERSHELL PROFILE
# --------------------------------------------------------------------------------------------------------


# PowerShell Profile Integration Function (Exported)

# --------------------------------------------------------------------------------------------------------
# CORE CONNECTIVITY TESTING (Enhanced)
# --------------------------------------------------------------------------------------------------------


# --------------------------------------------------------------------------------------------------------
# BACKGROUND SERVICE MANAGER
# --------------------------------------------------------------------------------------------------------

function Start-TunnelService {
    <#
    .SYNOPSIS
    Start the Ollama Tunnel background service

    .DESCRIPTION
    Starts the complete tunnel management service including:
    - SSH tunnel management
    - Model discovery
    - Health monitoring
    - Environment variable management
    #>
    [CmdletBinding()]
    param()
    
    if ($script:IsServiceRunning) {
        Write-Log "Tunnel service is already running"
        return
    }
    
    Initialize-DataPath
    # Load configuration from file if exists
    if (Test-Path $script:TunnelMonitorConfigFile) {
        try {
            $loadedConfig = Get-Content -Path $script:TunnelMonitorConfigFile -Raw | ConvertFrom-Json -AsHashtable
            foreach ($key in $loadedConfig.Keys) {
                if ($script:TunnelMonitorConfig.ContainsKey($key)) {
                    foreach ($subKey in $loadedConfig[$key].Keys) {
                        $script:TunnelMonitorConfig[$key][$subKey] = $loadedConfig[$key][$subKey]
                    }
                }
            }
            Write-Log "Configuration loaded from file"
        }
        catch {
            Write-Log "Failed to load configuration: $($_.Exception.Message)" -Level Warning
        }
    }
    
    Write-Log "Starting Ollama Tunnel Service..."

    # Start tunnel immediately (with silent fail when running as SYSTEM)
    $isSystem = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name -eq 'NT AUTHORITY\SYSTEM'
    $tunnelResult = if ($isSystem) {
        Start-ManagedSSHTunnel -SilentFail
    } else {
        Start-ManagedSSHTunnel
    }

    if ($tunnelResult) {
        Write-Log "SSH tunnel started successfully"

        # Initial model discovery
        if ($script:TunnelMonitorConfig.Models.DiscoveryEnabled) {
            Get-OllamaModels
        }
    }
    else {
        if ($isSystem) {
            Write-Log "SSH tunnel unavailable - service running in monitoring-only mode" -Level Warning
            Write-Log "Status APIs and monitoring features remain available" -Level Info
        } else {
            Write-Log "Failed to start SSH tunnel" -Level Error
        }
    }

    # Service is running regardless of tunnel status
    $script:IsServiceRunning = $true
    Write-Log "Tunnel service started in foreground mode"
}

function Stop-TunnelService {
    <#
    .SYNOPSIS
    Stop the Ollama Tunnel background service
    #>
    [CmdletBinding()]
    param()
    
    Write-Log "Stopping Ollama Tunnel Service..."
    
    # Stop background job
    if ($script:ServiceJob) {
        Stop-Job -Job $script:ServiceJob -ErrorAction SilentlyContinue
        Remove-Job -Job $script:ServiceJob -ErrorAction SilentlyContinue
        $script:ServiceJob = $null
    }
    
    # Stop SSH tunnel
    Stop-ManagedSSHTunnel
    
    $script:IsServiceRunning = $false
    Write-Log "Tunnel service stopped"
}

# --------------------------------------------------------------------------------------------------------
# WINDOWS SERVICE INSTALLATION
# --------------------------------------------------------------------------------------------------------

function Install-TunnelService {
    <#
    .SYNOPSIS
    Install the Ollama Tunnel Service as a Windows scheduled task

    .DESCRIPTION
    Installs a Windows scheduled task that runs at startup to manage SSH tunnels
    and Ollama model discovery. Requires Administrator privileges.

    .PARAMETER Uninstall
    Remove the service and clean up environment variables

    .PARAMETER StartNow
    Start the service immediately after installation

    .EXAMPLE
    Install-TunnelService -StartNow

    .EXAMPLE
    Install-TunnelService -Uninstall
    #>
    [CmdletBinding()]
    param(
        [switch]$Uninstall,
        [switch]$StartNow
    )

    $serviceName = $script:TunnelMonitorConfig.Service.Name

    # Check if running as administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Write-Error "Must run as Administrator to install/uninstall service"
        Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
        return
    }
    
    if ($Uninstall) {
        Write-Host "Uninstalling TunnelMonitorService..." -ForegroundColor Yellow

        try {
            # Stop the service if running
            Stop-ScheduledTask -TaskName $serviceName -ErrorAction SilentlyContinue

            # Remove scheduled task
            Unregister-ScheduledTask -TaskName $serviceName -Confirm:$false -ErrorAction SilentlyContinue
            Write-Host "  Removed scheduled task" -ForegroundColor Gray

            # Remove wake reconnect task
            $wakeTaskName = "OllamaTunnelWakeReconnect"
            if (Get-ScheduledTask -TaskName $wakeTaskName -ErrorAction SilentlyContinue) {
                Unregister-ScheduledTask -TaskName $wakeTaskName -Confirm:$false -ErrorAction SilentlyContinue
                Write-Host "  Removed wake reconnect task" -ForegroundColor Gray
            }

            # Clean up installed modules from Program Files
            $systemModulePath = "C:\Program Files\PowerShell\Modules\TunnelMonitor"
            if (Test-Path $systemModulePath) {
                try {
                    Remove-Item -Path $systemModulePath -Recurse -Force
                    Write-Host "  Removed module from system modules path" -ForegroundColor Gray
                }
                catch {
                    Write-Host "  Warning: Could not remove module files from $systemModulePath" -ForegroundColor Yellow
                    Write-Host "    You may need to manually delete this folder" -ForegroundColor Yellow
                }
            }

            # Clean up environment variables from all scopes
            $envVarsToRemove = @(
                'OLLAMA_AUTOCOMPLETE_MODEL', 'OLLAMA_CODER_MODEL',
                'OLLAMA_RERANKER_MODEL', 'OLLAMA_EMBEDDING_MODEL',
                'OLLAMA_TUNNEL_STATUS',
                'OLLAMA_API_URL', 'OLLAMA_MODEL_COUNT'
            )

            foreach ($envVar in $envVarsToRemove) {
                Remove-EnvVariable $envVar
                Write-Host "  Removed $envVar from all scopes" -ForegroundColor Gray
            }

            Write-Host "✅ Service '$serviceName' uninstalled successfully" -ForegroundColor Green
            return
        }
        catch {
            Write-Error "Failed to uninstall service: $($_.Exception.Message)"
            return
        }
    }
    
    # Create event log source if it doesn't exist (for service logging)
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists("TunnelMonitorService")) {
            [System.Diagnostics.EventLog]::CreateEventSource("TunnelMonitorService", "Application")
            Write-Host "  Created event log source" -ForegroundColor Gray
        }
    }
    catch {
        # May fail if not admin or source exists - continue anyway
        Write-Verbose "Event log source may already exist"
    }

    # Setup service SSH keys and configuration
    $serviceKeysPath = "C:\ProgramData\TunnelMonitor\keys"
    $serviceKeyFile = Join-Path $serviceKeysPath "service_key"
    $serviceConfigPath = "C:\ProgramData\TunnelMonitor\keys\ssh_config.json"

    # Check if SSH keys need to be generated
    if (-not (Test-Path $serviceKeyFile)) {
        Write-Host ""
        Write-Host "=== SSH Service Key Setup ===" -ForegroundColor Cyan
        Write-Host "No service SSH keys found. Generating new keys for SYSTEM account..." -ForegroundColor Yellow
        Write-Host ""

        # Create keys directory
        if (-not (Test-Path $serviceKeysPath)) {
            New-Item -Path $serviceKeysPath -ItemType Directory -Force | Out-Null
        }

        # Prompt for SSH connection details
        $sshHost = Read-Host "Enter SSH host (e.g., server.example.com or 192.168.1.100)"
        $sshUser = Read-Host "Enter SSH username (e.g., user)"

        if ([string]::IsNullOrWhiteSpace($sshHost) -or [string]::IsNullOrWhiteSpace($sshUser)) {
            Write-Error "SSH host and user are required"
            return
        }

        # Generate SSH key pair
        Write-Host "  Generating Ed25519 key pair..." -ForegroundColor Gray
        $sshKeyGenOutput = ssh-keygen -t ed25519 -f $serviceKeyFile -N '""' -C "TunnelMonitorService-SYSTEM" 2>&1

        if (-not (Test-Path $serviceKeyFile)) {
            Write-Error "Failed to generate SSH key: $sshKeyGenOutput"
            return
        }

        Write-Host "  SSH key pair generated" -ForegroundColor Green

        # Set SYSTEM ownership and permissions
        Write-Host "  Setting SYSTEM account permissions..." -ForegroundColor Gray

        try {
            # Get SYSTEM account
            $systemSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")
            $systemAccount = $systemSid.Translate([System.Security.Principal.NTAccount])

            # Set ownership to SYSTEM
            $acl = Get-Acl $serviceKeyFile
            $acl.SetOwner($systemAccount)
            Set-Acl -Path $serviceKeyFile -AclObject $acl

            # Remove all permissions and set SYSTEM-only access
            $acl = Get-Acl $serviceKeyFile
            $acl.SetAccessRuleProtection($true, $false)
            $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }

            # Grant SYSTEM full control
            $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $systemAccount, "FullControl", "Allow"
            )
            $acl.AddAccessRule($systemRule)

            # Grant Administrators read access
            $adminSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
            $adminAccount = $adminSid.Translate([System.Security.Principal.NTAccount])
            $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $adminAccount, "Read", "Allow"
            )
            $acl.AddAccessRule($adminRule)

            Set-Acl -Path $serviceKeyFile -AclObject $acl
            Write-Host "  Permissions set (SYSTEM: FullControl, Admins: Read)" -ForegroundColor Green
        }
        catch {
            Write-Warning "Could not set SYSTEM permissions: $($_.Exception.Message)"
            Write-Warning "Service may not be able to read the key. You may need to set permissions manually."
        }

        # Create service configuration
        $serviceConfig = @{
            RemoteHost = $sshHost
            RemoteUser = $sshUser
            PrivateKeyPath = $serviceKeyFile
            LocalPort = 11434
            RemotePort = 11434
        }

        # Save configuration
        $serviceConfig | ConvertTo-Json -Depth 10 | Set-Content $serviceConfigPath -Encoding UTF8
        Write-Host "  Configuration saved" -ForegroundColor Green

        # Display public key
        $publicKey = Get-Content "${serviceKeyFile}.pub"
        Write-Host ""
        Write-Host "=== PUBLIC KEY - Add this to your remote server ===" -ForegroundColor Cyan
        Write-Host $publicKey -ForegroundColor Yellow
        Write-Host ""
        Write-Host "On your remote server ($sshHost), run:" -ForegroundColor White
        Write-Host "  mkdir -p ~/.ssh && chmod 700 ~/.ssh" -ForegroundColor Gray
        Write-Host "  echo '$publicKey' >> ~/.ssh/authorized_keys" -ForegroundColor Gray
        Write-Host "  chmod 600 ~/.ssh/authorized_keys" -ForegroundColor Gray
        Write-Host ""

        # Copy to clipboard if possible
        try {
            $publicKey | Set-Clipboard
            Write-Host "  Public key copied to clipboard!" -ForegroundColor Green
        }
        catch {
            # Clipboard not available, continue anyway
        }

        # Prompt to continue
        Write-Host ""
        $continue = Read-Host "Have you added the public key to $sshHost ? (yes/no)"
        if ($continue -ne "yes" -and $continue -ne "y") {
            Write-Host ""
            Write-Host "Installation paused. Add the public key to your remote server, then run:" -ForegroundColor Yellow
            Write-Host "  Install-TunnelService -StartNow" -ForegroundColor Cyan
            return
        }

        Write-Host ""
    }
    elseif (-not (Test-Path $serviceConfigPath)) {
        Write-Host "⚠️  SSH keys exist but configuration is missing!" -ForegroundColor Yellow
        Write-Host "   Run Set-TunnelConfiguration to create the config, or delete the keys and reinstall." -ForegroundColor Gray
        return
    }

    try {
        Write-Host "Installing TunnelMonitorService..." -ForegroundColor Cyan

        # Create ProgramData directory for service data files (logs, keys, etc.)
        $serviceDataPath = Join-Path -Path $env:ProgramData -ChildPath "TunnelMonitor"
        if (-not (Test-Path $serviceDataPath)) {
            New-Item -Path $serviceDataPath -ItemType Directory -Force | Out-Null
        }

        # Install module to system PowerShell modules path for proper discovery
        Write-Host "  Installing module to system modules path..." -ForegroundColor Gray
        $systemModulePath = "C:\Program Files\PowerShell\Modules\TunnelMonitor"

        # Create module directory with version subfolder for proper module structure
        $moduleVersion = (Import-PowerShellDataFile -Path ($PSCommandPath -replace '\.psm1$', '.psd1')).ModuleVersion
        $versionedModulePath = Join-Path $systemModulePath $moduleVersion

        if (-not (Test-Path $versionedModulePath)) {
            New-Item -Path $versionedModulePath -ItemType Directory -Force | Out-Null
        }

        # Copy module files to system modules path
        $moduleSource = $PSCommandPath
        $manifestSource = $moduleSource -replace '\.psm1$', '.psd1'

        $moduleDest = Join-Path $versionedModulePath "TunnelMonitor.psm1"
        $manifestDest = Join-Path $versionedModulePath "TunnelMonitor.psd1"

        Copy-Item -Path $moduleSource -Destination $moduleDest -Force
        Copy-Item -Path $manifestSource -Destination $manifestDest -Force
        Write-Host "  Module installed to: $versionedModulePath" -ForegroundColor Gray
        Write-Host "  Data files location: $serviceDataPath" -ForegroundColor Gray

        # Create enhanced service script with health monitoring
        $serviceScript = @"
# TunnelMonitorService.ps1 - Enhanced Background Service Script with Health Monitoring
# This script runs at Windows startup and manages the Ollama tunnel with automatic recovery

# Start with Continue to allow initialization to proceed even with errors
`$ErrorActionPreference = 'Continue'
`$serviceStartTime = Get-Date

# Create startup debug log immediately
`$startupDebugLog = "C:\ProgramData\TunnelMonitor\startup_debug.log"
`$debugLog = Join-Path `$env:ProgramData "TunnelMonitor\service_debug.log"

# Ensure directory exists first
`$null = New-Item -Path "C:\ProgramData\TunnelMonitor" -ItemType Directory -Force -ErrorAction SilentlyContinue

# Startup debug function for immediate logging
function Write-StartupDebug {
    param([string]`$Message)
    try {
        `$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
        "`$timestamp | `$Message" | Out-File -FilePath `$startupDebugLog -Append -Encoding UTF8
    } catch {
        # Fail silently
    }
}

# Debug function for service logging - wrapped in try/catch for safety
function Write-DebugLog {
    param([string]`$Message)
    try {
        # Ensure directory exists
        `$debugDir = Split-Path `$debugLog -Parent
        if (-not (Test-Path `$debugDir)) {
            New-Item -Path `$debugDir -ItemType Directory -Force | Out-Null
        }
        # Write the log entry
        "`$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') - `$Message" | Out-File -FilePath `$debugLog -Append -Force
    } catch {
        # Fail silently - debug logging should never break the service
    }
}

Write-StartupDebug "===== SERVICE STARTING ====="
Write-StartupDebug "User: `$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
Write-StartupDebug "PATH: `$env:PATH"
Write-StartupDebug "Working Directory: `$(Get-Location)"
Write-StartupDebug "Computer: `$env:COMPUTERNAME"

# Test SSH availability immediately
`$sshPath = Get-Command ssh -ErrorAction SilentlyContinue
Write-StartupDebug "SSH via PATH: `$(if (`$sshPath) { `$sshPath.Source } else { 'NOT FOUND' })"

# Check standard SSH locations
`$sshLocations = @(
    "C:\Windows\System32\OpenSSH\ssh.exe",
    "C:\Program Files\OpenSSH\ssh.exe"
)
foreach (`$loc in `$sshLocations) {
    if (Test-Path `$loc) {
        Write-StartupDebug "SSH found at: `$loc"
    }
}

Write-DebugLog "====== SERVICE SCRIPT STARTING ======"
Write-DebugLog "Start time: `$serviceStartTime"
Write-DebugLog "Running as: `$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
Write-DebugLog "PS Version: `$(`$PSVersionTable.PSVersion)"
Write-DebugLog "Error action preference: `$ErrorActionPreference"

# Now set to Stop for main logic
`$ErrorActionPreference = 'Stop'
Write-DebugLog "Error action preference changed to: Stop"

try {
    # Log startup to event log - use "Application" source which always exists
    try {
        Write-EventLog -LogName Application -Source "Application" -EventId 1000 -EntryType Information -Message "TunnelMonitorService starting at `$serviceStartTime" -ErrorAction SilentlyContinue
        Write-DebugLog "Event log entry created"
    } catch {
        Write-DebugLog "Event log failed: `$(`$_.Exception.Message)"
    }

    # Import the TunnelMonitor module from system modules path
    Write-DebugLog "Importing TunnelMonitor module from system path"
    try {
        # First check if module is available
        `$module = Get-Module -ListAvailable -Name TunnelMonitor | Select-Object -First 1
        if (-not `$module) {
            throw "TunnelMonitor module not found in system modules path"
        }
        Write-DebugLog "Found module at: `$(`$module.Path)"

        Import-Module TunnelMonitor -Force
        Write-DebugLog "Module imported successfully"
    }
    catch {
        Write-DebugLog "MODULE IMPORT FAILED: `$(`$_.Exception.Message)"
        Write-DebugLog "Checking module paths: `$(`$env:PSModulePath)"
        throw
    }

    # Initialize logging
    Write-DebugLog "Initializing tunnel monitor data"
    # Initialize data path - must be hardcoded since we're in a separate script context
    `$dataPath = "C:\ProgramData\TunnelMonitor"
    if (-not (Test-Path `$dataPath)) {
        New-Item -Path `$dataPath -ItemType Directory -Force | Out-Null
    }
    Write-Log "TunnelMonitorService started at `$serviceStartTime"
    Write-DebugLog "Service initialization complete"

    # Wait for network availability before starting services
    Write-DebugLog "Checking network availability..."
    Write-Log "Waiting for network to become available..."
    Write-StartupDebug "Beginning network availability check"

    `$maxWaitTime = 60  # seconds
    `$waitStart = Get-Date
    `$networkReady = `$false

    while (((Get-Date) - `$waitStart).TotalSeconds -lt `$maxWaitTime) {
        try {
            # Test DNS resolution with local computer name
            `$null = [System.Net.Dns]::GetHostEntry(`$env:COMPUTERNAME)
            Write-StartupDebug "Local DNS resolution successful"

            # Test external connectivity (try common DNS servers)
            `$testHosts = @("8.8.8.8", "1.1.1.1", `$env:COMPUTERNAME)
            `$connected = `$false

            foreach (`$testHost in `$testHosts) {
                try {
                    `$null = Test-Connection -ComputerName `$testHost -Count 1 -ErrorAction Stop
                    `$connected = `$true
                    Write-StartupDebug "Network test successful to: `$testHost"
                    break
                }
                catch {
                    Write-StartupDebug "Network test failed to: `$testHost"
                }
            }

            if (`$connected) {
                `$networkReady = `$true
                Write-Log "Network is ready after `$([math]::Round(((Get-Date) - `$waitStart).TotalSeconds, 1)) seconds"
                Write-DebugLog "Network connectivity confirmed"
                Write-StartupDebug "Network is ready - proceeding with service startup"
                break
            }
        }
        catch {
            Write-DebugLog "Network check failed: `$(`$_.Exception.Message)" -Level Debug
            Write-StartupDebug "Waiting for network... Error: `$(`$_.Exception.Message)"
        }

        Start-Sleep -Seconds 5
    }

    if (-not `$networkReady) {
        Write-Log "Network availability timeout - proceeding anyway" -Level Warning
        Write-StartupDebug "Network timeout after `$maxWaitTime seconds - continuing"
    }


    # Load service SSH configuration and test accessibility
    Write-StartupDebug "Checking service SSH configuration"
    `$serviceConfigPath = "C:\ProgramData\TunnelMonitor\keys\ssh_config.json"
    if (Test-Path `$serviceConfigPath) {
        try {
            `$svcConfig = Get-Content `$serviceConfigPath -Raw | ConvertFrom-Json
            Write-StartupDebug "SSH Config - Host: `$(`$svcConfig.RemoteHost), User: `$(`$svcConfig.RemoteUser)"

            # Test key accessibility
            if (Test-Path `$svcConfig.PrivateKeyPath) {
                try {
                    `$keyTest = Get-Content `$svcConfig.PrivateKeyPath -ErrorAction Stop
                    Write-StartupDebug "SSH key readable: YES (`$((`$keyTest -join '').Length) characters)"
                }
                catch {
                    Write-StartupDebug "SSH key readable: NO - `$(`$_.Exception.Message)"
                }
            }
            else {
                Write-StartupDebug "SSH key not found at: `$(`$svcConfig.PrivateKeyPath)"
            }
        }
        catch {
            Write-StartupDebug "Failed to load SSH config: `$(`$_.Exception.Message)"
        }
    }
    else {
        Write-StartupDebug "No SSH configuration found at: `$serviceConfigPath"
    }

    # Start the tunnel service (with silent fail for SYSTEM resilience)
    Write-DebugLog "Starting tunnel service"
    Write-StartupDebug "Calling Start-TunnelService"
    Start-TunnelService
    Write-Log "Tunnel service initialization completed"
    Write-DebugLog "Tunnel service started"

    # Health monitoring loop - continues even if tunnel fails
    `$consecutiveFailures = 0
    `$maxConsecutiveFailures = 5
    `$tunnelAvailable = `$false
    `$loopCount = 0

    Write-DebugLog "Entering main monitoring loop"
    while (`$true) {
        `$loopCount++
        Write-DebugLog "Loop iteration `$loopCount starting"
        Start-Sleep -Seconds 300  # Check every 5 minutes

        try {
            # Check tunnel health
            `$health = Get-TunnelStatus -Check Full
            `$tunnelAvailable = (`$health.Status -eq "Operational")

            if (`$health.Status -in "Not Installed", "Stopped", "Starting", "Partial", "Failed") {
                # Check if event handler is already handling a restart
                if (`$script:RestartInProgress) {
                    Write-DebugLog "Restart already in progress via exit event, skipping health check restart"
                }
                else {
                    `$consecutiveFailures++
                    Write-Log "Tunnel unhealthy (failure #`$consecutiveFailures)" -Level Warning

                    if (`$consecutiveFailures -ge `$maxConsecutiveFailures) {
                        Write-Log "Max consecutive failures reached, attempting restart with silent fail" -Level Warning

                        # Set flag to prevent event handler from conflicting
                        `$script:RestartInProgress = `$true
                        try {
                            # Try to restart with silent fail - service continues even if SSH fails
                            Stop-ManagedSSHTunnel -Force
                            Start-Sleep -Seconds 10
                            `$result = Start-ManagedSSHTunnel -SilentFail

                            if (`$result) {
                                Write-Log "Tunnel restarted successfully via health check"
                                `$consecutiveFailures = 0
                                `$tunnelAvailable = `$true
                            } else {
                                Write-Log "Tunnel restart failed - service continuing without tunnel" -Level Warning
                                `$tunnelAvailable = `$false
                                # Reset counter to prevent constant restart attempts
                                `$consecutiveFailures = 3  # Keep some failures to retry periodically
                            }
                        }
                        finally {
                            `$script:RestartInProgress = `$false
                        }
                    }
                    else {
                        # Try soft restart with silent fail (only if not already in progress)
                        if (-not `$script:RestartInProgress) {
                            `$result = Start-ManagedSSHTunnel -SilentFail
                            if (`$result) {
                                `$tunnelAvailable = `$true
                            }
                        }
                    }
                }
            }
            else {
                # Reset failure counter on success
                if (`$consecutiveFailures -gt 0) {
                    Write-Log "Tunnel recovered after `$consecutiveFailures failures"
                    `$consecutiveFailures = 0
                }
            }

            # Periodic model discovery
            if (`$script:TunnelMonitorConfig.Models.DiscoveryEnabled) {
                `$timeSinceLastDiscovery = if (`$script:DiscoveredModels.LastDiscovery) {
                    ((Get-Date) - `$script:DiscoveredModels.LastDiscovery).TotalSeconds
                } else { 999999 }

                if (`$timeSinceLastDiscovery -gt `$script:TunnelMonitorConfig.Models.DiscoveryInterval) {
                    Get-OllamaModels | Out-Null
                }
            }
        }
        catch {
            Write-Log "Health check error: `$(`$_.Exception.Message)" -Level Error
            Write-DebugLog "Health check error in loop `${loopCount}: `$(`$_.Exception.Message)"
            `$consecutiveFailures++
        }

        Write-DebugLog "Loop iteration `$loopCount completed"
    }
}
catch {
    `$errorMsg = "Service startup failed: `$(`$_.Exception.Message)"
    Write-DebugLog "FATAL ERROR: `$errorMsg"
    Write-DebugLog "Stack trace: `$(`$_.ScriptStackTrace)"

    try {
        Write-EventLog -LogName Application -Source "Application" -EventId 1001 -EntryType Error -Message `$errorMsg -ErrorAction SilentlyContinue
    } catch {
        Write-DebugLog "Could not write to event log: `$(`$_.Exception.Message)"
    }

    try {
        Write-Log `$errorMsg -Level Error
    } catch {
        Write-DebugLog "Could not write to service log: `$(`$_.Exception.Message)"
    }

    Write-DebugLog "SERVICE TERMINATING DUE TO ERROR"
    throw
}
finally {
    Write-DebugLog "====== SERVICE SCRIPT EXITING ======"
    Write-DebugLog "Exit time: `$(Get-Date)"
}
"@
        
        $serviceScriptPath = Join-Path $serviceDataPath "TunnelMonitorService.ps1"
        $serviceScript | Set-Content $serviceScriptPath -Encoding UTF8
        Write-Host "  Service script created: $serviceScriptPath" -ForegroundColor Gray
        
        # Create scheduled task with enhanced settings - Use PowerShell 7 (pwsh.exe) with full path
        $pwshPath = "C:\Program Files\PowerShell\7\pwsh.exe"
        if (-not (Test-Path $pwshPath)) {
            # Fallback to searching for pwsh.exe
            $pwshPath = (Get-Command pwsh -ErrorAction SilentlyContinue).Source
            if (-not $pwshPath) {
                Write-Error "PowerShell 7 (pwsh.exe) not found. Please install PowerShell 7."
                return
            }
        }
        $serviceAction = New-ScheduledTaskAction -Execute $pwshPath -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -File `"$serviceScriptPath`""
        $serviceTrigger = New-ScheduledTaskTrigger -AtStartup

        # Enhanced settings with restart on failure
        $serviceSettings = New-ScheduledTaskSettingsSet `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries `
            -StartWhenAvailable `
            -ExecutionTimeLimit (New-TimeSpan -Hours 0) `
            -RestartCount 3 `
            -RestartInterval (New-TimeSpan -Minutes 1)

        # Run as SYSTEM with highest privileges
        $servicePrincipal = New-ScheduledTaskPrincipal `
            -UserId "NT AUTHORITY\SYSTEM" `
            -LogonType ServiceAccount `
            -RunLevel Highest
        
        Register-ScheduledTask -TaskName $serviceName -Action $serviceAction -Trigger $serviceTrigger -Settings $serviceSettings -Principal $servicePrincipal -Force | Out-Null

        # Register power event tasks for wake/login reconnection
        Write-Host "  Registering power event handlers..." -ForegroundColor Gray

        # Task 1: Restart tunnel on system wake
        $wakeTaskName = "OllamaTunnelWakeReconnect"
        try {
            $existingTask = Get-ScheduledTask -TaskName $wakeTaskName -ErrorAction SilentlyContinue
            if ($existingTask) {
                Unregister-ScheduledTask -TaskName $wakeTaskName -Confirm:$false
            }

            $wakeAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument @"
-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -Command "& {
    Import-Module TunnelMonitor
    Write-EventLog -LogName Application -Source 'Application' -EventId 1002 -EntryType Information -Message 'System wake detected - restarting SSH tunnel'
    Stop-ManagedSSHTunnel -Force
    Start-Sleep -Seconds 2
    Start-ManagedSSHTunnel
    Get-OllamaModels
}"
"@

            $wakeTrigger = New-ScheduledTaskTrigger -AtStartup
            $wakeTrigger.Delay = "PT10S"  # 10 second delay after wake

            $loginTrigger = New-ScheduledTaskTrigger -AtLogOn
            $loginTrigger.Delay = "PT5S"  # 5 second delay after login

            $wakeSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                -Hidden -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -Priority 6

            $wakePrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest

            Register-ScheduledTask -TaskName $wakeTaskName `
                -Action $wakeAction `
                -Trigger @($wakeTrigger, $loginTrigger) `
                -Settings $wakeSettings `
                -Principal $wakePrincipal `
                -Description "Restart Ollama SSH tunnel after system wake or user login" | Out-Null

            Write-Host "    ✅ Wake/login reconnect task registered" -ForegroundColor Gray
        }
        catch {
            Write-Host "    ⚠️  Failed to register wake task: $($_.Exception.Message)" -ForegroundColor Yellow
        }

        Write-Host "✅ TunnelMonitorService installed successfully!" -ForegroundColor Green
        Write-Host ""
        Write-Host "📋 Service Details:" -ForegroundColor White
        Write-Host "   Name: $serviceName" -ForegroundColor Gray
        Write-Host "   Script: $serviceScriptPath" -ForegroundColor Gray
        Write-Host "   Data Path: $serviceDataPath" -ForegroundColor Gray
        Write-Host "   Logs: $serviceDataPath\service.log" -ForegroundColor Gray
        Write-Host ""
        Write-Host "🎮 Management Commands:" -ForegroundColor White
        Write-Host "   Start:  Start-ScheduledTask -TaskName '$serviceName'" -ForegroundColor Cyan
        Write-Host "   Stop:   Stop-ScheduledTask -TaskName '$serviceName'" -ForegroundColor Cyan
        Write-Host "   Status: Get-ScheduledTask -TaskName '$serviceName'" -ForegroundColor Cyan
        Write-Host "   Logs:   Get-Content '$serviceDataPath\service.log' -Tail 20" -ForegroundColor Cyan

        if ($StartNow) {
            Write-Host ""
            Write-Host "🚀 Starting service now..." -ForegroundColor Yellow
            Start-ScheduledTask -TaskName $serviceName
            Start-Sleep -Seconds 3

            $task = Get-ScheduledTask -TaskName $serviceName
            $taskInfo = Get-ScheduledTaskInfo -TaskName $serviceName

            $statusColor = switch ($task.State) {
                'Running' { 'Green' }
                'Ready' { 'Yellow' }
                default { 'Red' }
            }

            Write-Host "   Service State: $($task.State)" -ForegroundColor $statusColor

            if ($taskInfo.LastRunTime) {
                Write-Host "   Last Run: $($taskInfo.LastRunTime)" -ForegroundColor Gray
            }

            # Quick health check
            Start-Sleep -Seconds 2
            $serviceLogFile = Join-Path $serviceDataPath "service.log"
            if (Test-Path $serviceLogFile) {
                $recentLogs = Get-Content $serviceLogFile -Tail 3
                if ($recentLogs) {
                    Write-Host ""
                    Write-Host "📜 Recent log entries:" -ForegroundColor White
                    $recentLogs | ForEach-Object { Write-Host "   $_" -ForegroundColor Gray }
                }
            }
        }
        else {
            Write-Host ""
            Write-Host "⏳ Service will start automatically at next boot" -ForegroundColor Yellow
            Write-Host "   Or start now with: Start-ScheduledTask -TaskName '$serviceName'" -ForegroundColor Cyan
        }
        
    }
    catch {
        Write-Error "Failed to install service: $($_.Exception.Message)"
    }
}

# --------------------------------------------------------------------------------------------------------
# MODULE INITIALIZATION AND EXPORTS
# --------------------------------------------------------------------------------------------------------

# Initialize module on load
Initialize-DataPath

# Load configuration from file if exists
if (Test-Path $script:TunnelMonitorConfigFile) {
    try {
        $loadedConfig = Get-Content -Path $script:TunnelMonitorConfigFile -Raw | ConvertFrom-Json -AsHashtable
        foreach ($key in $loadedConfig.Keys) {
            if ($script:TunnelMonitorConfig.ContainsKey($key)) {
                foreach ($subKey in $loadedConfig[$key].Keys) {
                    $script:TunnelMonitorConfig[$key][$subKey] = $loadedConfig[$key][$subKey]
                }
            }
        }
    }
    catch {
        # Silent fail on module load
    }
}


# Module exports are handled by the manifest (.psd1) file

# Module loaded silently - no output to avoid profile clutter
# For help, use: Get-Command -Module TunnelMonitor
