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

        [string]$SSHUser = "user",

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

# Export module members
Export-ModuleMember -Function @(
    'Get-OllamaStatus',
    'Get-OllamaModelProfile',
    'Get-OllamaLoadedModels',
    'Get-OllamaModels',
    'Get-RemoteGPUStatus',
    'Test-OllamaAPI',
    'Get-OllamaModelInfo',
    'Format-OllamaStatus'
)
