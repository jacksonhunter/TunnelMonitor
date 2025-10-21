# TunnelMonitor.psd1 - Module Manifest

@{
    # Script module or binary module file associated with this manifest
    RootModule = 'TunnelMonitor.psm1'

    # Version number of this module
    ModuleVersion = '1.0.0'
    
    # Supported PSEditions
    CompatiblePSEditions = @('Core')
    
    # ID used to uniquely identify this module
    GUID = '87654321-4321-4321-4321-123456789087'
    
    # Author of this module
    Author = 'PowerAuger Team'
    
    # Company or vendor of this module
    CompanyName = 'Unknown'
    
    # Copyright statement for this module
    Copyright = '(c) 2025 PowerAuger Team. All rights reserved.'
    
    # Description of the functionality provided by this module
    Description = 'General-purpose PowerShell module for managing multiple SSH tunnels with service-specific health monitoring, automatic recovery, and Windows service integration. Refactored from OllamaTunnelMonitor v1.7.0.'
    
    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '7.1'
    
    # Functions to export from this module (12 public functions)
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

        # Status (1)
        'Get-TunnelStatus',                # Get service and API status

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
            Tags = @('SSH', 'Tunnel', 'Monitoring', 'Multi-Service', 'Network', 'Service-Management', 'Health-Check')
            
            # ReleaseNotes of this module
            ReleaseNotes = @'
1.0.0 - Initial Release (Refactored from OllamaTunnelMonitor v1.7.0):
- Ground-up refactor to support multiple services via single SSH tunnel
- Service abstraction layer for pluggable health checks
- Inherits battle-tested SSH tunnel management from 7 versions of development
- Windows service integration with SYSTEM account support
- Power event handling (sleep/wake recovery)
- Automatic log rotation (10MB max, 7-day retention)
- SSH resilience features (keepalive, auto-retry, graceful degradation)
- Comprehensive startup debugging and error handling
- Security hardening (input sanitization, SSH key validation)
- Network availability checking at boot
- Foundation for multi-service tunnel management

Note: Ollama-specific features moved to companion OllamaTools module
'@
        }
    }
}