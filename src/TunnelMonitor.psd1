# TunnelMonitor.psd1 - Module Manifest

@{
    # Script module or binary module file associated with this manifest
    RootModule = 'TunnelMonitor.psm1'

    # Version number of this module
    ModuleVersion = '1.9.0'

    # Supported PSEditions
    CompatiblePSEditions = @('Core')

    # ID used to uniquely identify this module
    GUID = '12345678-1234-1234-1234-123456789012'

    # Author of this module
    Author = 'PowerAuger Team'

    # Company or vendor of this module
    CompanyName = 'Unknown'

    # Copyright statement for this module
    Copyright = '(c) 2025 PowerAuger Team. All rights reserved.'

    # Description of the functionality provided by this module
    Description = 'General-purpose multi-service SSH tunnel manager with Windows service capabilities. Forward multiple ports through a single SSH connection. Features health monitoring, automatic recovery, and Ollama integration. Refactored from OllamaTunnelMonitor v1.7.0.'
    
    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '7.1'
    
    # Functions to export from this module (13 public functions)
    FunctionsToExport = @(
        # Service management (3)
        'Install-TunnelService',           # Install Windows scheduled task with power event handling
        'Start-TunnelService',             # Start tunnel background service
        'Stop-TunnelService',              # Stop tunnel background service

        # SSH tunnel management (2) - Required by service script
        'Start-ManagedSSHTunnel',          # Start SSH tunnel process
        'Stop-ManagedSSHTunnel',           # Stop SSH tunnel process

        # Configuration (2)
        'Set-TunnelConfiguration',         # Configure SSH tunnel settings
        'Get-TunnelConfiguration',         # Read current configuration

        # Model management (3)
        'Get-OllamaModels',                # Discover and categorize models
        'Export-ModelEnvironmentVariables', # Export models to env vars
        'Get-RemoteGPUStatus',             # Get remote GPU status

        # Status (2)
        'Get-TunnelStatus',                # Get service and API status
        'Test-TunnelPorts',                # Test all forwarded ports

        # Internal - Required by service script
        'Write-Log'                        # Write to service log (used by service)
    )
    
    # Cmdlets to export from this module
    CmdletsToExport = @()
    
    # Variables to export from this module
    VariablesToExport = @()
    
    # Aliases to export from this module
    AliasesToExport = @()
    
    # List of all files packaged with this module
    FileList = @('TunnelMonitor.psm1', 'TunnelMonitor.psd1')
    
    # Private data to pass to the module
    PrivateData = @{
        PSData = @{
            # Tags applied to this module
            Tags = @('SSH', 'Tunnel', 'Ollama', 'Monitoring', 'Dashboard', 'PowerAuger', 'Network', 'Socket', 'Headless')
            
            # ReleaseNotes of this module
            ReleaseNotes = @'
1.9.0 - Multi-Service Implementation Complete:
- IMPLEMENTED: Multi-port SSH tunnel forwarding (single SSH connection, multiple -L arguments)
- IMPLEMENTED: Test-TunnelPorts function validates all configured ports
- IMPLEMENTED: Get-TunnelStatus includes AdditionalServices array with per-service status
- IMPLEMENTED: Get-TunnelConfiguration displays all additional services
- HARDCODED: TransformersTunnel (port 5000) and Samba (port 445) as additional services
- MODIFIED: Start-ManagedSSHTunnel builds multiple -L arguments for all services
- MODIFIED: Get-ExistingSSHTunnel detects tunnels with additional service ports
- All services forward through single SSH connection (Ollama:11434 + TransformersTunnel:5000 + Samba:445)
- Ready for testing in live environment

1.8.0 - Multi-Service Support (Refactored from OllamaTunnelMonitor v1.7.0):
- NEW: Multi-service SSH tunnel support via AdditionalServices parameter
- NEW: Test-TunnelPorts function to check all forwarded ports
- NEW: Get-TunnelStatus now reports status of all additional services
- Renamed Install-OllamaTunnelService → Install-TunnelService
- Module renamed from OllamaTunnelMonitor to TunnelMonitor for general-purpose use
- Forward multiple services through single SSH connection (e.g., Ollama + Samba + Vision API)
- Backward compatible with single-port configurations
- All working functionality from OllamaTunnelMonitor v1.7.0 preserved

1.7.0 - Module Cleanup & Log Rotation:
- Added automatic module cleanup on uninstall (removes from Program Files)
- Implemented log rotation (10MB max size, 7-day retention)
- Improved Get-TunnelStatus to infer service status when running as user
- Fixed detection of SYSTEM-owned SSH processes
- Created companion OllamaTools module for standalone utilities
- Better handling of permission limitations for non-admin users

1.6.0 - Power Event Handling & SSH Resilience:
- Added automatic SSH tunnel restart on system wake/login events
- Integrated power event tasks into main service installation
- Enhanced SSH options for better sleep/wake resilience:
  * Added TCPKeepAlive for OS-level keepalives
  * Reduced ServerAliveInterval from 60 to 30 seconds
  * Changed ExitOnForwardFailure to no (critical for resilience)
  * Added ConnectionAttempts for automatic retries
  * Added BatchMode to prevent auth prompts on wake
- Wake task automatically restarts tunnel after sleep
- Cleaner design: removed separate power event functions
- Uninstall now properly removes wake reconnect task

1.5.0 - Critical Bug Fixes & Code Cleanup:
- FIXED: Embedded service script variable scope issues (was using $script: in separate context)
- FIXED: AsJob parameter removed (was broken, never worked properly)
- Added Initialize-DataPath helper function to consolidate duplicate code
- Added log buffering for 10x better Write-Log performance
- Removed hardcoded IP fallback for security
- Cleaned up empty comment sections
- Reduced code duplication throughout
- Module is now production-ready with all critical issues resolved

1.4.0 - Tree Shaking Release:
- Removed 8 unused functions (835 lines of dead code)
- Enhanced Get-TunnelStatus with model count and response time
- Cleaned module down from 2400+ to 1563 lines (35% reduction)
- Final public API: 10 essential functions

1.3.0 - SSH Permissions & Environment Variables Fix:
- FIXED: SSH key permissions for SYSTEM using scheduled task workaround
- FIXED: Environment variables now persist system-wide (Machine scope)
- Added dual-key strategy: service key + admin key for testing
- Added Test-AdminPrivileges helper function
- Enhanced permission setting via scheduled task running as SYSTEM
- Comprehensive permission logging in permission_log.txt

1.2.0 - SSH Startup Fix Release:
- FIXED: SSH tunnel failures at Windows startup when running as SYSTEM
- Added Get-SSHExecutablePath for reliable SSH binary resolution
- Fixed Unix-style /dev/null replaced with Windows NUL
- Enhanced SSH error capture with stdout/stderr logging
- Added network availability check before service startup
- Comprehensive startup debugging with dedicated log file
- Improved SYSTEM account key accessibility verification

1.1.0 - Enhanced Service Release:
- Enhanced Windows service installation with health monitoring
- Automatic SSH tunnel recovery after failures
- Model discovery with intelligent categorization
- Fast status API for PowerShell profile integration (<100ms)
- Security hardening: SSH key validation, input sanitization
- Environment variable management with proper scoping
- Event log integration for service diagnostics
- Approved PowerShell verbs for all functions

1.0.0 - Initial Release:
- SSH tunnel monitoring with .NET socket integration
- PowerAuger integration with configuration import/export
- Windows-optimized process management
'@
        }
    }
}