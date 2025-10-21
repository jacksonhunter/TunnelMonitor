# OllamaTools.psd1 - Module Manifest for Ollama utility functions

@{
    # Script module or binary module file associated with this manifest
    RootModule = 'OllamaTools.psm1'

    # Version number of this module
    ModuleVersion = '1.0.0'

    # Supported PSEditions
    CompatiblePSEditions = @('Core', 'Desktop')

    # ID used to uniquely identify this module
    GUID = 'a1b2c3d4-5678-90ab-cdef-123456789abc'

    # Author of this module
    Author = 'PowerAuger Team'

    # Company or vendor of this module
    CompanyName = 'Unknown'

    # Copyright statement for this module
    Copyright = '(c) 2025 PowerAuger Team. All rights reserved.'

    # Description of the functionality provided by this module
    Description = 'Utility functions for Ollama API interaction, model management, memory profiling, and status monitoring. Complements OllamaTunnelMonitor with standalone tools.'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Functions to export from this module
    FunctionsToExport = @(
        'Get-OllamaStatus',           # Quick API status check
        'Get-OllamaModelProfile',     # Profile models with Ollama's native API
        'Get-OllamaLoadedModels',     # Check currently loaded models
        'Get-OllamaModels',            # List and categorize models
        'Get-RemoteGPUStatus',         # GPU status via SSH
        'Test-OllamaAPI',              # Simple API connectivity test
        'Get-OllamaModelInfo',         # Detailed model information
        'Format-OllamaStatus'          # Pretty status display
    )

    # Cmdlets to export from this module
    CmdletsToExport = @()

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module
    AliasesToExport = @()

    # List of all files packaged with this module
    FileList = @('OllamaTools.psm1', 'OllamaTools.psd1')

    # Private data to pass to the module
    PrivateData = @{
        PSData = @{
            # Tags applied to this module
            Tags = @('Ollama', 'API', 'LLM', 'AI', 'Monitoring', 'GPU', 'Memory', 'Models')

            # ReleaseNotes of this module
            ReleaseNotes = @'
1.0.0 - Initial Release:
- Extracted utility functions from OllamaTunnelMonitor
- Added Get-OllamaMemorySize for memory profiling
- Enhanced model information retrieval
- Standalone tools that work without tunnel service
'@
        }
    }
}