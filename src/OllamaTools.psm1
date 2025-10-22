# OllamaTools.psm1 - Utility functions for Ollama API interaction
# ========================================================================================================
# STANDALONE OLLAMA UTILITIES
# Functions for model management, memory profiling, and API interaction
# ========================================================================================================

#Requires -Version 5.1

# Default Ollama API endpoint
$script:OllamaApiUrl = if ($env:OLLAMA_API_URL) { $env:OLLAMA_API_URL } else { "http://localhost:11434" }

function Get-OllamaStatus {
    <#
    .SYNOPSIS
    Quick status check of Ollama API

    .DESCRIPTION
    Performs a fast health check of the Ollama API endpoint

    .PARAMETER ApiUrl
    The Ollama API URL (defaults to http://localhost:11434)

    .EXAMPLE
    Get-OllamaStatus

    .EXAMPLE
    Get-OllamaStatus -ApiUrl http://remote:11434
    #>
    [CmdletBinding()]
    param(
        [string]$ApiUrl = $script:OllamaApiUrl
    )

    $status = [PSCustomObject]@{
        Available = $false
        ResponseTimeMs = -1
        Version = $null
        Models = 0
        Timestamp = Get-Date
    }

    try {
        $start = Get-Date

        # Try version endpoint first (fastest)
        $version = Invoke-RestMethod -Uri "$ApiUrl/api/version" -TimeoutSec 2 -ErrorAction Stop
        $status.Available = $true
        $status.Version = $version.version

        # Try to get model count
        try {
            $models = Invoke-RestMethod -Uri "$ApiUrl/api/tags" -TimeoutSec 2 -ErrorAction Stop
            $status.Models = @($models.models).Count
        }
        catch {
            # Models endpoint failed, but API is still available
        }

        $status.ResponseTimeMs = [math]::Round(((Get-Date) - $start).TotalMilliseconds, 1)
    }
    catch {
        # API not available
    }

    return $status
}

function Get-OllamaModelProfile {
    <#
    .SYNOPSIS
    Profile Ollama models for memory usage and capabilities

    .DESCRIPTION
    Uses native Ollama API to get model memory usage, context windows, and performance metrics

    .PARAMETER Models
    Array of model names to profile. If not specified, profiles categorized models only.

    .PARAMETER TestContextSizes
    Test different context window sizes to measure memory scaling

    .PARAMETER ApiUrl
    The Ollama API URL (defaults to http://localhost:11434)

    .EXAMPLE
    Get-OllamaModelProfile

    .EXAMPLE
    Get-OllamaModelProfile -TestContextSizes @(2048, 4096, 8192)
    #>
    [CmdletBinding()]
    param(
        [string[]]$Models,
        [int[]]$TestContextSizes,
        [string]$ApiUrl = $script:OllamaApiUrl
    )

    # Get list of models if not specified - use categorized models
    if (-not $Models) {
        try {
            # Get categorized models from main module
            if (-not (Get-Module OllamaTunnelMonitor)) {
                Import-Module "$PSScriptRoot\OllamaTunnelMonitor.psd1" -Force -ErrorAction SilentlyContinue
            }

            $categorized = OllamaTunnelMonitor\Get-OllamaModels
            if ($categorized) {
                $Models = @()
                if ($categorized.AutoComplete) { $Models += $categorized.AutoComplete }
                if ($categorized.Coder) { $Models += $categorized.Coder }
                if ($categorized.Reranker) { $Models += $categorized.Reranker }
                if ($categorized.Embedding) { $Models += $categorized.Embedding }
                Write-Host "Profiling $($Models.Count) categorized models" -ForegroundColor Cyan
            }
            else {
                Write-Error "No categorized models found"
                return
            }
        }
        catch {
            Write-Error "Failed to get model list: $_"
            return
        }
    }

    $results = @()

    foreach ($modelName in $Models) {
        Write-Host "`nProfiling: $modelName" -ForegroundColor Yellow

        # Get model details first
        try {
            $modelInfo = Invoke-RestMethod -Uri "$ApiUrl/api/show" -Method Post `
                -Body (@{name = $modelName; verbose = $true} | ConvertTo-Json) `
                -ContentType "application/json" -TimeoutSec 30

            # Extract key information
            $profile = [PSCustomObject]@{
                ModelName = $modelName
                Family = $modelInfo.details.family
                Format = $modelInfo.details.format
                ParameterSize = $modelInfo.details.parameter_size
                Quantization = $modelInfo.details.quantization_level

                # Context window info
                DefaultContext = $null
                MaxContext = $null

                # Memory measurements
                MemoryTests = @()
            }

            # Extract context info from model_info
            if ($modelInfo.model_info) {
                # Try different keys where context might be stored
                $contextKeys = @(
                    "llama.context_length",
                    "gemma.context_length",
                    "qwen.context_length",
                    "bert.context_length",
                    "context_length",
                    "max_position_embeddings"
                )

                foreach ($key in $contextKeys) {
                    if ($modelInfo.model_info.$key) {
                        $profile.DefaultContext = $modelInfo.model_info.$key
                        $profile.MaxContext = $modelInfo.model_info.$key
                        break
                    }
                }
            }

            # Parse parameters for context info
            if ($modelInfo.parameters -match 'num_ctx\s+(\d+)') {
                $profile.DefaultContext = [int]$matches[1]
            }

            Write-Host "  Model Info: $($profile.ParameterSize) $($profile.Quantization) $($profile.Family)"
            Write-Host "  Default Context: $($profile.DefaultContext ?? 'Unknown')"

        }
        catch {
            Write-Warning "Failed to get model info for $modelName : $_"
            continue
        }

        # Test memory usage
        $contextSizesToTest = if ($TestContextSizes) {
            $TestContextSizes
        } elseif ($profile.DefaultContext) {
            @($profile.DefaultContext)  # Just test default
        } else {
            @(4096)  # Fallback default
        }

        foreach ($contextSize in $contextSizesToTest) {
            Write-Host "  Testing with context=$contextSize..." -NoNewline

            # First ensure model is unloaded
            try {
                if ($modelName -match 'embed') {
                    $null = Invoke-RestMethod -Uri "$ApiUrl/api/embeddings" -Method Post `
                        -Body (@{model=$modelName; prompt=""; keep_alive=0} | ConvertTo-Json) `
                        -ContentType "application/json" -TimeoutSec 5 -ErrorAction SilentlyContinue
                } else {
                    $null = Invoke-RestMethod -Uri "$ApiUrl/api/generate" -Method Post `
                        -Body (@{model=$modelName; prompt=""; keep_alive=0} | ConvertTo-Json) `
                        -ContentType "application/json" -TimeoutSec 5 -ErrorAction SilentlyContinue
                }
                Start-Sleep -Seconds 2
            }
            catch {
                # Ignore unload errors
            }

            # Load model with specific context size
            $loadStart = Get-Date
            try {
                if ($modelName -match 'embed') {
                    # Use embeddings for embedding models
                    $loadBody = @{
                        model = $modelName
                        prompt = "test"
                    } | ConvertTo-Json

                    $response = Invoke-RestMethod -Uri "$ApiUrl/api/embeddings" -Method Post `
                        -Body $loadBody -ContentType "application/json" -TimeoutSec 30
                }
                else {
                    # Use generate for other models with num_ctx option
                    $loadBody = @{
                        model = $modelName
                        prompt = "test"
                        options = @{
                            num_ctx = $contextSize
                        }
                        keep_alive = "10s"  # Keep loaded briefly for measurement
                    } | ConvertTo-Json -Depth 3

                    $response = Invoke-RestMethod -Uri "$ApiUrl/api/generate" -Method Post `
                        -Body $loadBody -ContentType "application/json" -TimeoutSec 30
                }

                $loadTime = ((Get-Date) - $loadStart).TotalSeconds
                Write-Host " Loaded ($([math]::Round($loadTime, 1))s)"

                # Get memory usage from /api/ps
                Start-Sleep -Seconds 1  # Let memory stabilize
                $psInfo = Invoke-RestMethod -Uri "$ApiUrl/api/ps" -TimeoutSec 5

                $loadedModel = $psInfo.models | Where-Object { $_.name -eq $modelName }

                if ($loadedModel) {
                    $memoryMB = [math]::Round($loadedModel.size / 1MB, 0)
                    $vramMB = [math]::Round($loadedModel.size_vram / 1MB, 0)

                    Write-Host "    Memory: ${memoryMB}MB total, ${vramMB}MB VRAM"

                    # Add to results
                    $profile.MemoryTests += [PSCustomObject]@{
                        ContextSize = $contextSize
                        TotalMemoryMB = $memoryMB
                        VRAMMemoryMB = $vramMB
                        LoadTimeSeconds = [math]::Round($loadTime, 1)
                        ActualContext = $loadedModel.context_length
                        ExpiresAt = $loadedModel.expires_at
                    }
                }
                else {
                    Write-Warning "Model not found in ps output"
                }

            }
            catch {
                Write-Host " Failed"
                Write-Warning "Failed to load $modelName with context=$contextSize : $_"
            }
            finally {
                # Unload model
                try {
                    if ($modelName -match 'embed') {
                        $null = Invoke-RestMethod -Uri "$ApiUrl/api/embeddings" -Method Post `
                            -Body (@{model=$modelName; prompt=""; keep_alive=0} | ConvertTo-Json) `
                            -ContentType "application/json" -TimeoutSec 5 -ErrorAction SilentlyContinue
                    } else {
                        $null = Invoke-RestMethod -Uri "$ApiUrl/api/generate" -Method Post `
                            -Body (@{model=$modelName; prompt=""; keep_alive=0} | ConvertTo-Json) `
                            -ContentType "application/json" -TimeoutSec 5 -ErrorAction SilentlyContinue
                    }
                }
                catch {
                    # Ignore
                }
            }
        }

        $results += $profile
    }

    # Create comparison table
    if ($results.Count -gt 0) {
        Write-Host "`n=== Model Comparison Summary ===" -ForegroundColor Cyan

        $summary = $results | ForEach-Object {
            $model = $_
            $defaultMem = $model.MemoryTests | Select-Object -First 1

            [PSCustomObject]@{
                Model = $model.ModelName
                Parameters = $model.ParameterSize
                Quantization = $model.Quantization
                "Context" = $defaultMem.ActualContext ?? $model.DefaultContext ?? "Unknown"
                "Memory (MB)" = $defaultMem.VRAMMemoryMB ?? $defaultMem.TotalMemoryMB ?? "N/A"
                "Memory (GB)" = if ($defaultMem.VRAMMemoryMB) { [math]::Round($defaultMem.VRAMMemoryMB / 1024, 2) } else { "N/A" }
                "Load Time (s)" = $defaultMem.LoadTimeSeconds ?? "N/A"
            }
        }

        $summary | Format-Table -AutoSize
    }

    return $results
}

# Lightweight function to just check what's currently loaded
function Get-OllamaLoadedModels {
    <#
    .SYNOPSIS
    Get currently loaded models and their memory usage

    .DESCRIPTION
    Quick check of what models are loaded and how much memory they're using

    .PARAMETER ApiUrl
    The Ollama API URL

    .EXAMPLE
    Get-OllamaLoadedModels
    #>
    [CmdletBinding()]
    param(
        [string]$ApiUrl = $script:OllamaApiUrl
    )

    try {
        $psInfo = Invoke-RestMethod -Uri "$ApiUrl/api/ps" -TimeoutSec 5

        if ($psInfo.models.Count -eq 0) {
            Write-Host "No models currently loaded" -ForegroundColor Yellow
            return
        }

        $psInfo.models | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.name
                "Memory (GB)" = [math]::Round($_.size / 1GB, 2)
                "VRAM (GB)" = [math]::Round($_.size_vram / 1GB, 2)
                Parameters = $_.details.parameter_size
                Quantization = $_.details.quantization_level
                Context = $_.context_length
                "Expires At" = [DateTime]$_.expires_at
            }
        } | Format-Table -AutoSize

    }
    catch {
        Write-Error "Failed to get loaded models: $_"
    }
}

# Helper function to get GPU memory stats (kept for old function compatibility)
function Get-GPUMemory {
    param(
        [string]$SSHHost,
        [string]$SSHUser
    )

    if (-not $SSHHost -or -not $SSHUser) {
        Write-Error "SSH host and user required for GPU monitoring"
        return $null
    }

    $sshCmd = "nvidia-smi --query-gpu=memory.total,memory.free,memory.used --format=csv,noheader,nounits"
    $result = ssh "$SSHUser@$SSHHost" $sshCmd 2>$null

    if ($LASTEXITCODE -eq 0 -and $result) {
        $parts = $result -split ','
        return [PSCustomObject]@{
            TotalMB = [int]$parts[0]
            FreeMB = [int]$parts[1]
            UsedMB = [int]$parts[2]
            UsedPercent = [math]::Round(([int]$parts[2] / [int]$parts[0]) * 100, 1)
        }
    }
    return $null
}

function Get-OllamaModels {
    <#
    .SYNOPSIS
    List and categorize available Ollama models

    .DESCRIPTION
    Retrieves all models from Ollama API and categorizes them by type

    .PARAMETER ApiUrl
    The Ollama API URL

    .PARAMETER Categorize
    Automatically categorize models by type

    .EXAMPLE
    Get-OllamaModels

    .EXAMPLE
    Get-OllamaModels -Categorize
    #>
    [CmdletBinding()]
    param(
        [string]$ApiUrl = $script:OllamaApiUrl,
        [switch]$Categorize
    )

    try {
        $response = Invoke-RestMethod -Uri "$ApiUrl/api/tags" -TimeoutSec 10 -ErrorAction Stop
        $models = $response.models

        if ($Categorize) {
            $categorized = @{
                Coder = @()
                AutoComplete = @()
                Embedding = @()
                Reranker = @()
                General = @()
                Vision = @()
            }

            foreach ($model in $models) {
                $name = $model.name.ToLower()

                if ($name -match 'code|coder|program') {
                    $categorized.Coder += $model
                }
                elseif ($name -match 'autocomplete|complete') {
                    $categorized.AutoComplete += $model
                }
                elseif ($name -match 'embed') {
                    $categorized.Embedding += $model
                }
                elseif ($name -match 'rerank') {
                    $categorized.Reranker += $model
                }
                elseif ($name -match 'vision|llava') {
                    $categorized.Vision += $model
                }
                else {
                    $categorized.General += $model
                }
            }

            return $categorized
        }
        else {
            return $models
        }
    }
    catch {
        Write-Error "Failed to retrieve models: $_"
        return @()
    }
}

function Get-RemoteGPUStatus {
    <#
    .SYNOPSIS
    Get GPU status from remote machine via SSH

    .DESCRIPTION
    Connects via SSH to retrieve nvidia-smi output.
    Uses tunnel configuration from environment if parameters not specified.

    .PARAMETER SSHHost
    Remote host address (uses POWERAUGER_LINUX_HOST env var if not specified)

    .PARAMETER SSHUser
    SSH username (uses POWERAUGER_SSH_USER env var if not specified)

    .PARAMETER SSHKeyPath
    Path to SSH private key (searches standard locations if not specified)

    .EXAMPLE
    Get-RemoteGPUStatus

    .EXAMPLE
    Get-RemoteGPUStatus -SSHHost server.local -SSHUser admin -SSHKeyPath ~/.ssh/id_rsa
    #>
    [CmdletBinding()]
    param(
        [string]$SSHHost = "192.168.50.194",

        [string]$SSHUser,

        [string]$SSHKeyPath
    )

    # Find SSH key if not specified
    if (-not $SSHKeyPath) {
        $keyPaths = @(
            "$env:USERPROFILE\.ssh\ollama_tunnel_rsa",
            "$env:USERPROFILE\.ssh\ollama_tunnel_admin_rsa",
            "$env:USERPROFILE\.ssh\id_rsa",
            "$env:USERPROFILE\.ssh\id_ed25519"
        )

        foreach ($path in $keyPaths) {
            if (Test-Path $path) {
                $SSHKeyPath = $path
                break
            }
        }
    }

    $sshArgs = @(
        "$SSHUser@$SSHHost",
        "nvidia-smi --query-gpu=name,memory.used,memory.total,utilization.gpu,temperature.gpu --format=csv"
    )

    if ($SSHKeyPath -and (Test-Path $SSHKeyPath)) {
        $sshArgs = @("-i", $SSHKeyPath) + $sshArgs
    }

    try {
        $result = & ssh $sshArgs 2>$null
        if ($LASTEXITCODE -eq 0) {
            $result | ConvertFrom-Csv
        }
        else {
            Write-Error "SSH command failed"
            return $null
        }
    }
    catch {
        Write-Error "Failed to connect: $_"
        return $null
    }
}

function Test-OllamaAPI {
    <#
    .SYNOPSIS
    Simple API connectivity test

    .DESCRIPTION
    Quick test to see if Ollama API is responding

    .PARAMETER ApiUrl
    The Ollama API URL

    .PARAMETER Quiet
    Return boolean instead of object

    .EXAMPLE
    Test-OllamaAPI

    .EXAMPLE
    if (Test-OllamaAPI -Quiet) { Write-Host "API is up" }
    #>
    [CmdletBinding()]
    param(
        [string]$ApiUrl = $script:OllamaApiUrl,
        [switch]$Quiet
    )

    try {
        $null = Invoke-RestMethod -Uri "$ApiUrl/api/version" -TimeoutSec 2 -ErrorAction Stop

        if ($Quiet) {
            return $true
        }
        else {
            return [PSCustomObject]@{
                Success = $true
                ApiUrl = $ApiUrl
                Timestamp = Get-Date
            }
        }
    }
    catch {
        if ($Quiet) {
            return $false
        }
        else {
            return [PSCustomObject]@{
                Success = $false
                ApiUrl = $ApiUrl
                Error = $_.Exception.Message
                Timestamp = Get-Date
            }
        }
    }
}

function Get-OllamaModelInfo {
    <#
    .SYNOPSIS
    Get detailed information about a specific model

    .DESCRIPTION
    Retrieves comprehensive details about an Ollama model including parameters,
    template, and configuration

    .PARAMETER ModelName
    Name of the model

    .PARAMETER ApiUrl
    The Ollama API URL

    .EXAMPLE
    Get-OllamaModelInfo -ModelName "llama2:7b"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ModelName,

        [string]$ApiUrl = $script:OllamaApiUrl
    )

    try {
        $response = Invoke-RestMethod -Uri "$ApiUrl/api/show" -Method Post -Body (@{
            name = $ModelName
        } | ConvertTo-Json) -ContentType "application/json" -ErrorAction Stop

        # Parse useful information
        $info = [PSCustomObject]@{
            Name = $ModelName
            Family = $response.details.family
            ParameterSize = $response.details.parameter_size
            Quantization = $response.details.quantization_level
            Format = $response.details.format
            License = $response.license
            Template = $response.template
            System = $response.system
            Parameters = @{}
        }

        # Extract parameters if available
        if ($response.parameters) {
            $params = $response.parameters -split "`n"
            foreach ($param in $params) {
                if ($param -match '(\w+)\s+(.+)') {
                    $info.Parameters[$matches[1]] = $matches[2]
                }
            }
        }

        # Add model file info
        if ($response.modelfile) {
            $info | Add-Member -NotePropertyName "ModelFile" -NotePropertyValue $response.modelfile
        }

        return $info
    }
    catch {
        Write-Error "Failed to get model info: $_"
        return $null
    }
}

function Format-OllamaStatus {
    <#
    .SYNOPSIS
    Pretty-print Ollama status information

    .DESCRIPTION
    Formats Ollama API status in a readable format for display

    .PARAMETER Status
    Status object from Get-OllamaStatus

    .PARAMETER Compact
    Use compact single-line format

    .EXAMPLE
    Get-OllamaStatus | Format-OllamaStatus

    .EXAMPLE
    Format-OllamaStatus -Status (Get-OllamaStatus) -Compact
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        $Status,

        [switch]$Compact
    )

    process {
        if (-not $Status) {
            $Status = Get-OllamaStatus
        }

        if ($Compact) {
            if ($Status.Available) {
                Write-Host "✅ Ollama API: " -NoNewline -ForegroundColor Green
                Write-Host "Online" -ForegroundColor Green -NoNewline
                Write-Host " | Models: $($Status.Models)" -NoNewline
                Write-Host " | Response: $($Status.ResponseTimeMs)ms" -ForegroundColor DarkGray
            }
            else {
                Write-Host "❌ Ollama API: " -NoNewline -ForegroundColor Red
                Write-Host "Offline" -ForegroundColor Red
            }
        }
        else {
            Write-Host ""
            Write-Host "Ollama API Status" -ForegroundColor Cyan
            Write-Host "═════════════════" -ForegroundColor Cyan

            if ($Status.Available) {
                Write-Host "  Status:       " -NoNewline
                Write-Host "Online ✅" -ForegroundColor Green

                if ($Status.Version) {
                    Write-Host "  Version:      $($Status.Version)"
                }

                Write-Host "  Models:       $($Status.Models)"
                Write-Host "  Response:     $($Status.ResponseTimeMs)ms"

                if ($Status.ResponseTimeMs -lt 100) {
                    Write-Host "  Performance:  Excellent" -ForegroundColor Green
                }
                elseif ($Status.ResponseTimeMs -lt 500) {
                    Write-Host "  Performance:  Good" -ForegroundColor Yellow
                }
                else {
                    Write-Host "  Performance:  Slow" -ForegroundColor Red
                }
            }
            else {
                Write-Host "  Status:       " -NoNewline
                Write-Host "Offline ❌" -ForegroundColor Red
                Write-Host "  API URL:      $script:OllamaApiUrl" -ForegroundColor Gray
            }

            Write-Host "  Timestamp:    $($Status.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
            Write-Host ""
        }
    }
}

# ========================================================================================================
# SSH KEY MANAGEMENT FUNCTIONS (for TunnelMonitor/OllamaTunnelMonitor service setup)
# ========================================================================================================

function Install-ServiceSSHKey {
    <#
    .SYNOPSIS
    Generate dedicated SSH keys for the tunnel service (requires admin)

    .DESCRIPTION
    Creates service-specific SSH keys that SYSTEM account can access safely.
    User must manually configure the remote server with the generated public key.
    Keys are stored in C:\ProgramData\OllamaTunnelMonitor\keys

    .PARAMETER RemoteHost
    The SSH server hostname or IP address

    .PARAMETER RemoteUser
    The SSH username on the remote server

    .PARAMETER LocalPort
    Local port to bind for tunnel (default: 11434)

    .PARAMETER RemotePort
    Remote port to tunnel to (default: 11434)

    .PARAMETER Force
    Regenerate keys even if they already exist

    .PARAMETER CreateAdminKey
    Also create admin-accessible key for testing

    .EXAMPLE
    Install-ServiceSSHKey -RemoteHost "192.168.1.100" -RemoteUser "ollama"

    .EXAMPLE
    Install-ServiceSSHKey -RemoteHost "server.local" -RemoteUser "tunnel" -Force -CreateAdminKey
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RemoteHost,

        [Parameter(Mandatory)]
        [string]$RemoteUser,

        [int]$LocalPort = 11434,
        [int]$RemotePort = 11434,

        [switch]$Force,
        [switch]$CreateAdminKey
    )

    # Verify running as admin
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Must run as Administrator to install service SSH keys"
    }

    $serviceKeyDir = "C:\ProgramData\OllamaTunnelMonitor\keys"
    $privateKeyPath = Join-Path $serviceKeyDir "ollama_service_key"
    $publicKeyPath = "$privateKeyPath.pub"
    $configPath = Join-Path $serviceKeyDir "ssh_config.json"

    # Check if keys already exist
    if ((Test-Path $privateKeyPath) -and -not $Force) {
        Write-Host "Service SSH key already exists at: $privateKeyPath" -ForegroundColor Yellow
        Write-Host "   Use -Force to regenerate (will require updating remote server)" -ForegroundColor Gray

        # Show existing public key
        if (Test-Path $publicKeyPath) {
            Write-Host ""
            Write-Host "Current public key (already configured?):" -ForegroundColor Cyan
            Write-Host "================================================================" -ForegroundColor Gray
            Get-Content $publicKeyPath | Write-Host -ForegroundColor White
            Write-Host "================================================================" -ForegroundColor Gray
        }
        return
    }

    Write-Host "Setting up dedicated SSH keys for Ollama Tunnel Service..." -ForegroundColor Cyan
    Write-Host "   Target: $RemoteUser@$RemoteHost" -ForegroundColor Gray
    Write-Host "   Tunnel: localhost:$LocalPort -> ${RemoteHost}:$RemotePort" -ForegroundColor Gray

    # Create secure key directory
    if (-not (Test-Path $serviceKeyDir)) {
        New-Item -Path $serviceKeyDir -ItemType Directory -Force | Out-Null
    }

    # Set proper ACLs (SYSTEM + Administrators only)
    try {
        $acl = Get-Acl $serviceKeyDir
        $acl.SetAccessRuleProtection($true, $false)  # Disable inheritance, remove existing

        # Clear existing ACL entries
        $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }

        # Add SYSTEM full control
        $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
        )
        $acl.SetAccessRule($systemRule)

        # Add Administrators full control
        $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
        )
        $acl.SetAccessRule($adminRule)

        Set-Acl -Path $serviceKeyDir -AclObject $acl
        Write-Host "Secured key directory with SYSTEM + Admin access only" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to set secure ACLs: $($_.Exception.Message)"
    }

    # Generate SSH key pair
    try {
        Write-Host "Generating ED25519 key pair..." -ForegroundColor Yellow

        # Remove existing keys if Force specified
        if ($Force) {
            Remove-Item $privateKeyPath, $publicKeyPath -ErrorAction SilentlyContinue
        }

        # Generate new key with no passphrase (required for service)
        $sshKeyGenArgs = @(
            "-t", "ed25519"
            "-f", $privateKeyPath
            "-N", '""'  # No passphrase
            "-C", "OllamaTunnelService@$env:COMPUTERNAME"
            "-q"  # Quiet mode
        )

        $result = Start-Process -FilePath "ssh-keygen" -ArgumentList $sshKeyGenArgs -Wait -PassThru -WindowStyle Hidden

        if ($result.ExitCode -ne 0) {
            throw "ssh-keygen failed with exit code: $($result.ExitCode)"
        }

        if (-not (Test-Path $privateKeyPath) -or -not (Test-Path $publicKeyPath)) {
            throw "SSH key generation failed - key files not created"
        }

        Write-Host "SSH key pair generated successfully" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to generate SSH keys: $($_.Exception.Message)"
        Write-Host "Make sure OpenSSH client is installed: winget install Microsoft.OpenSSH.Beta" -ForegroundColor Yellow
        return
    }

    # Set proper SSH key file permissions for OpenSSH compliance
    Write-Host "Setting secure permissions for SYSTEM account..." -ForegroundColor Yellow

    try {
        # First, set basic permissions that admins can still access temporarily
        Write-Host "  Setting initial permissions..." -ForegroundColor Gray
        $null = icacls $privateKeyPath /inheritance:r /Q 2>&1
        $null = icacls $privateKeyPath /grant "NT AUTHORITY\SYSTEM:(F)" /Q 2>&1
        $null = icacls $privateKeyPath /grant "BUILTIN\Administrators:(R)" /Q 2>&1

        # For public key, allow broader access
        $null = icacls $publicKeyPath /inheritance:r /Q 2>&1
        $null = icacls $publicKeyPath /grant "NT AUTHORITY\SYSTEM:(F)" /Q 2>&1
        $null = icacls $publicKeyPath /grant "BUILTIN\Administrators:(R)" /Q 2>&1

        Write-Host "  Base permissions set (SYSTEM: Full, Admins: Read)" -ForegroundColor Gray

        # Create a scheduled task to run AS SYSTEM to set final strict permissions
        Write-Host "  Finalizing strict SSH permissions via SYSTEM account..." -ForegroundColor Gray

        $tempScriptPath = Join-Path $env:TEMP "fix_ssh_perms_$(Get-Random).ps1"
        $scriptContent = @"
# Running as SYSTEM to set OpenSSH-compliant permissions
`$keyPath = '$privateKeyPath'
`$pubPath = '$publicKeyPath'
`$logPath = '$serviceKeyDir\permission_log.txt'

try {
    # Set strict permissions for private key (SYSTEM only)
    & icacls `"`$keyPath`" /inheritance:r /grant `"NT AUTHORITY\SYSTEM:(F)`" /Q

    # Public key can have broader access
    & icacls `"`$pubPath`" /inheritance:r /grant `"NT AUTHORITY\SYSTEM:(F)`" /grant `"BUILTIN\Administrators:(R)`" /Q

    # Log the result
    `$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    `$acl = Get-Acl `$keyPath
    `$accessList = `$acl.Access | ForEach-Object { `"`$(`$_.IdentityReference): `$(`$_.FileSystemRights)`" }
    `"[`$timestamp] Permissions set by SYSTEM: `$(`$accessList -join '; ')`" | Out-File -FilePath `$logPath -Append
}
catch {
    `"[`$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Error setting permissions: `$(`$_.Exception.Message)`" | Out-File -FilePath `$logPath -Append
}
"@

        # Write the temporary script
        $scriptContent | Set-Content -Path $tempScriptPath -Encoding UTF8

        # Create and run a scheduled task as SYSTEM
        $taskName = "TempFixSSHKeyPerms_$(Get-Random)"
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -NoProfile -File `"$tempScriptPath`""
        $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $task = Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Force -ErrorAction Stop

        # Run the task
        Start-ScheduledTask -TaskName $taskName
        Start-Sleep -Seconds 3

        # Clean up
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item $tempScriptPath -ErrorAction SilentlyContinue

        # Verify final permissions
        $finalAcl = icacls $privateKeyPath 2>&1
        Write-Host "  Final key permissions:" -ForegroundColor Gray
        foreach ($line in ($finalAcl -split "`n")) {
            if ($line.Trim()) {
                Write-Host "    $line" -ForegroundColor DarkGray
            }
        }

        Write-Host "SSH key permissions configured for SYSTEM account" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to set strict permissions: $($_.Exception.Message)"
        Write-Host "  You may need to manually set permissions using psexec" -ForegroundColor Yellow
    }

    # Save configuration for service
    $sshConfig = @{
        RemoteHost = $RemoteHost
        RemoteUser = $RemoteUser
        LocalPort = $LocalPort
        RemotePort = $RemotePort
        PrivateKeyPath = $privateKeyPath
        PublicKeyPath = $publicKeyPath
        CreatedDate = Get-Date
        CreatedBy = $env:USERNAME
    }

    try {
        $sshConfig | ConvertTo-Json -Depth 5 | Set-Content $configPath -Encoding UTF8
        Write-Host "SSH configuration saved" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to save SSH configuration: $($_.Exception.Message)"
    }

    # Create admin key if requested (for testing/debugging)
    if ($CreateAdminKey) {
        Write-Host ""
        Write-Host "Creating additional admin-accessible key for testing..." -ForegroundColor Cyan

        $adminKeyPath = Join-Path $serviceKeyDir "ollama_admin_key"
        $adminPubPath = "$adminKeyPath.pub"

        try {
            # Generate admin key
            $adminKeyGenArgs = @(
                "-t", "ed25519"
                "-f", $adminKeyPath
                "-N", '""'  # No passphrase
                "-C", "OllamaAdmin@$env:COMPUTERNAME"
                "-q"  # Quiet mode
            )

            $result = Start-Process -FilePath "ssh-keygen" -ArgumentList $adminKeyGenArgs -Wait -PassThru -WindowStyle Hidden

            if ($result.ExitCode -eq 0 -and (Test-Path $adminKeyPath)) {
                # Set admin-friendly permissions
                $null = icacls $adminKeyPath /inheritance:r /Q 2>&1
                $null = icacls $adminKeyPath /grant "BUILTIN\Administrators:(F)" /Q 2>&1
                $null = icacls $adminKeyPath /grant "NT AUTHORITY\SYSTEM:(R)" /Q 2>&1

                # Public key can be read by all
                $null = icacls $adminPubPath /inheritance:r /Q 2>&1
                $null = icacls $adminPubPath /grant "BUILTIN\Administrators:(F)" /Q 2>&1
                $null = icacls $adminPubPath /grant "NT AUTHORITY\SYSTEM:(R)" /Q 2>&1

                Write-Host "Admin key created successfully" -ForegroundColor Green
                Write-Host "   Private key: $adminKeyPath" -ForegroundColor Gray
                Write-Host "   Public key: $adminPubPath" -ForegroundColor Gray
                Write-Host ""
                Write-Host "Admin public key (also add this to remote server):" -ForegroundColor Yellow
                $adminPubKey = Get-Content $adminPubPath
                Write-Host $adminPubKey -ForegroundColor Yellow
                Write-Host ""
                Write-Host "Remember to add BOTH public keys to the remote server!" -ForegroundColor Yellow
                Write-Host "   The service key for automatic startup" -ForegroundColor Gray
                Write-Host "   The admin key for manual testing" -ForegroundColor Gray
            }
            else {
                Write-Warning "Failed to generate admin key"
            }
        }
        catch {
            Write-Warning "Admin key generation failed: $($_.Exception.Message)"
        }
    }

    # Display setup instructions
    Write-Host ""
    Write-Host "NEXT STEPS - Remote Server Setup Required:" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Gray
    Write-Host ""
    Write-Host "1. Copy this PUBLIC key:" -ForegroundColor White
    Write-Host ""

    $publicKey = Get-Content $publicKeyPath
    Write-Host $publicKey -ForegroundColor Yellow
    Write-Host ""

    Write-Host "2. Add it to the remote server:" -ForegroundColor White
    Write-Host "   ssh $RemoteUser@$RemoteHost" -ForegroundColor Gray
    Write-Host "   echo '$publicKey' >> ~/.ssh/authorized_keys" -ForegroundColor Gray
    Write-Host ""

    Write-Host "3. Test the connection:" -ForegroundColor White
    Write-Host "   Test-ServiceSSHConnection" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "4. Install the tunnel service:" -ForegroundColor White
    Write-Host "   Install-TunnelService  (or Install-OllamaTunnelService)" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Gray

    # Store public key in clipboard if possible
    try {
        $publicKey | Set-Clipboard
        Write-Host "Public key copied to clipboard!" -ForegroundColor Green
    }
    catch {
        Write-Host "Manually copy the public key above" -ForegroundColor Yellow
    }
}

function Test-ServiceSSHConnection {
    <#
    .SYNOPSIS
    Test SSH connection using service keys

    .DESCRIPTION
    Validates that the service SSH keys are properly configured and can connect to the remote server

    .EXAMPLE
    Test-ServiceSSHConnection
    #>
    [CmdletBinding()]
    param()

    $configPath = "C:\ProgramData\OllamaTunnelMonitor\keys\ssh_config.json"

    if (-not (Test-Path $configPath)) {
        Write-Error "No SSH configuration found. Run Install-ServiceSSHKey first."
        return $false
    }

    try {
        $config = Get-Content $configPath -Raw | ConvertFrom-Json -AsHashtable

        Write-Host "Testing SSH connection to $($config.RemoteUser)@$($config.RemoteHost)..." -ForegroundColor Cyan

        $sshArgs = @(
            "-i", $config.PrivateKeyPath
            "-o", "ConnectTimeout=10"
            "-o", "StrictHostKeyChecking=no"
            "-o", "UserKnownHostsFile=/dev/null"
            "-o", "BatchMode=yes"  # No interactive prompts
            "$($config.RemoteUser)@$($config.RemoteHost)"
            "echo 'SSH connection successful'"
        )

        $result = Start-Process -FilePath "ssh" -ArgumentList $sshArgs -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput "$env:TEMP\ssh_test.out" -RedirectStandardError "$env:TEMP\ssh_test.err"

        if ($result.ExitCode -eq 0) {
            Write-Host "SSH connection successful!" -ForegroundColor Green
            Write-Host "Ready to install tunnel service: Install-TunnelService (or Install-OllamaTunnelService)" -ForegroundColor Cyan
            return $true
        }
        else {
            Write-Host "SSH connection failed (Exit code: $($result.ExitCode))" -ForegroundColor Red

            if (Test-Path "$env:TEMP\ssh_test.err") {
                $errorOutput = Get-Content "$env:TEMP\ssh_test.err" -Raw
                if ($errorOutput) {
                    Write-Host "Error details:" -ForegroundColor Yellow
                    Write-Host $errorOutput -ForegroundColor Gray
                }
            }

            Write-Host ""
            Write-Host "Troubleshooting:" -ForegroundColor Yellow
            Write-Host "   1. Verify public key was added to remote ~/.ssh/authorized_keys" -ForegroundColor Gray
            Write-Host "   2. Check remote SSH service is running" -ForegroundColor Gray
            Write-Host "   3. Verify firewall allows SSH (port 22)" -ForegroundColor Gray
            Write-Host "   4. Test manual connection: ssh -i `"$($config.PrivateKeyPath)`" $($config.RemoteUser)@$($config.RemoteHost)" -ForegroundColor Gray

            return $false
        }
    }
    catch {
        Write-Error "SSH test failed: $($_.Exception.Message)"
        return $false
    }
    finally {
        # Clean up temp files
        Remove-Item "$env:TEMP\ssh_test.out", "$env:TEMP\ssh_test.err" -ErrorAction SilentlyContinue
    }
}

function Get-ServiceSSHConfiguration {
    <#
    .SYNOPSIS
    Show current service SSH configuration

    .DESCRIPTION
    Displays the current SSH configuration for the tunnel service including connection details and public key

    .EXAMPLE
    Get-ServiceSSHConfiguration
    #>
    [CmdletBinding()]
    param()

    $configPath = "C:\ProgramData\OllamaTunnelMonitor\keys\ssh_config.json"
    $privateKeyPath = "C:\ProgramData\OllamaTunnelMonitor\keys\ollama_service_key"
    $publicKeyPath = "$privateKeyPath.pub"

    if (-not (Test-Path $configPath)) {
        Write-Host "No SSH configuration found" -ForegroundColor Red
        Write-Host "   Run: Install-ServiceSSHKey -RemoteHost <host> -RemoteUser <user>" -ForegroundColor Yellow
        return
    }

    try {
        $config = Get-Content $configPath -Raw | ConvertFrom-Json -AsHashtable

        Write-Host "Service SSH Configuration:" -ForegroundColor Cyan
        Write-Host "================================================================" -ForegroundColor Gray
        Write-Host "Remote Host: $($config.RemoteHost)" -ForegroundColor White
        Write-Host "Remote User: $($config.RemoteUser)" -ForegroundColor White
        Write-Host "Local Port:  $($config.LocalPort)" -ForegroundColor White
        Write-Host "Remote Port: $($config.RemotePort)" -ForegroundColor White
        Write-Host "Private Key: $($config.PrivateKeyPath)" -ForegroundColor White
        Write-Host "Created:     $($config.CreatedDate) by $($config.CreatedBy)" -ForegroundColor Gray
        Write-Host ""

        # Check key files exist
        $privateKeyExists = Test-Path $config.PrivateKeyPath
        $publicKeyExists = Test-Path $config.PublicKeyPath

        Write-Host "Key Status:" -ForegroundColor White
        Write-Host "  Private Key: $(if ($privateKeyExists) { 'Found' } else { 'Missing' })" -ForegroundColor $(if ($privateKeyExists) { 'Green' } else { 'Red' })
        Write-Host "  Public Key:  $(if ($publicKeyExists) { 'Found' } else { 'Missing' })" -ForegroundColor $(if ($publicKeyExists) { 'Green' } else { 'Red' })

        if ($publicKeyExists) {
            Write-Host ""
            Write-Host "Public Key (for remote server):" -ForegroundColor Cyan
            Write-Host "================================================================" -ForegroundColor Gray
            Get-Content $publicKeyPath | Write-Host -ForegroundColor Yellow
            Write-Host "================================================================" -ForegroundColor Gray
        }

        Write-Host ""
        Write-Host "Test Connection: Test-ServiceSSHConnection" -ForegroundColor Cyan
        Write-Host "Install Service: Install-TunnelService (or Install-OllamaTunnelService)" -ForegroundColor Cyan

        return $config
    }
    catch {
        Write-Error "Failed to read SSH configuration: $($_.Exception.Message)"
    }
}

function Remove-ServiceSSHKey {
    <#
    .SYNOPSIS
    Remove service SSH keys and configuration (requires admin)

    .DESCRIPTION
    Removes the dedicated SSH keys and configuration used by the tunnel service

    .PARAMETER Force
    Skip confirmation prompt

    .EXAMPLE
    Remove-ServiceSSHKey

    .EXAMPLE
    Remove-ServiceSSHKey -Force
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([switch]$Force)

    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Must run as Administrator to remove service SSH keys"
    }

    $serviceKeyDir = "C:\ProgramData\OllamaTunnelMonitor\keys"

    if (-not (Test-Path $serviceKeyDir)) {
        Write-Host "No service SSH keys found to remove" -ForegroundColor Blue
        return
    }

    if (-not $Force) {
        Write-Host "This will remove all service SSH keys and configuration" -ForegroundColor Yellow
        Write-Host "   The tunnel service will stop working until keys are regenerated" -ForegroundColor Gray
        $confirm = Read-Host "Continue? (y/N)"
        if ($confirm -ne 'y' -and $confirm -ne 'Y') {
            Write-Host "Operation cancelled" -ForegroundColor Gray
            return
        }
    }

    try {
        Remove-Item $serviceKeyDir -Recurse -Force
        Write-Host "Service SSH keys removed" -ForegroundColor Green
        Write-Host "   Remember to remove the public key from the remote server" -ForegroundColor Yellow
    }
    catch {
        Write-Error "Failed to remove SSH keys: $($_.Exception.Message)"
    }
}

# Export module members
Export-ModuleMember -Function @(
    'Get-OllamaStatus',
    'Get-OllamaModelProfile',
    'Get-OllamaLoadedModels',
    'Get-OllamaModels',
    'Get-RemoteGPUStatus',
    'Test-OllamaAPI',
    'Get-OllamaModelInfo',
    'Format-OllamaStatus',
    'Install-ServiceSSHKey',
    'Test-ServiceSSHConnection',
    'Get-ServiceSSHConfiguration',
    'Remove-ServiceSSHKey'
)
