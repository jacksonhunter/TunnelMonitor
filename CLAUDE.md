# TunnelMonitor - Project Guidelines

## Project Overview
General-purpose PowerShell module for managing multiple SSH tunnels with service-specific health monitoring, automatic recovery, and Windows service integration.

**Key Differentiator:** Unlike OllamaTunnelMonitor (single-purpose Ollama tunnel), TunnelMonitor is a **multi-service SSH tunnel manager** that can forward any number of ports with independent health checks per service.

## Current Version: 1.0.0-alpha (Refactored from OllamaTunnelMonitor v1.7.0)

**Status:** Architecture design phase - extracting Ollama-specific code to OllamaTools

## Origin Story - Lessons Learned from OllamaTunnelMonitor

This project is a **ground-up refactor** of OllamaTunnelMonitor, incorporating 7 versions worth of hard-won lessons:

### What We Learned (The Hard Way)

#### 1. SSH on Windows as SYSTEM is Hard
- **Problem:** SYSTEM account has minimal PATH, SSH keys need special permissions
- **Solution:**
  - Hardcoded SSH binary search paths (C:\Windows\System32\OpenSSH\ssh.exe, etc.)
  - Scheduled task permission setting for SSH keys (SYSTEM must own its keys)
  - Dedicated service keys separate from admin keys

#### 2. Network Timing at Boot is Critical
- **Problem:** Service starts before network is ready
- **Solution:**
  - 60-second network availability check with DNS resolution tests
  - Graceful degradation (service runs in monitoring mode if SSH fails)
  - SilentFail mode for resilience

#### 3. SSH Tunnels Die on Sleep/Wake
- **Problem:** SSH connection doesn't survive laptop sleep
- **Solution:**
  - Power event handlers (wake/login scheduled tasks)
  - Enhanced SSH keepalive options (TCPKeepAlive, ServerAliveInterval=30)
  - ExitOnForwardFailure=no for temporary network blips
  - Process exit event handlers for instant crash detection

#### 4. Windows-Specific SSH Gotchas
- **Problem:** Unix assumptions break on Windows
- **Solution:**
  - Use `NUL` not `/dev/null`
  - Capture stdout/stderr to temp files (can't redirect to NUL in Start-Process)
  - PowerShell 7 required (Core edition) for proper SSH support

#### 5. Environment Variables are Tricky
- **Problem:** Process scope vs Machine scope, SYSTEM vs User context
- **Solution:**
  - Auto-detect privilege level (admin = Machine scope, user = User scope)
  - Never persist SSH credentials (Process scope only)
  - Check all scopes when reading (Process > User > Machine)

#### 6. Service Scripts Need Special Care
- **Problem:** Embedded service script has separate scope from module
- **Solution:**
  - Never use `$script:` variables in embedded service scripts
  - Hardcode paths (can't rely on module state)
  - Import module explicitly in service context
  - Comprehensive debug logging from the start

#### 7. Health Monitoring Must Be Async
- **Problem:** Blocking health checks slow down status API
- **Solution:** (TO BE IMPLEMENTED in TunnelMonitor)
  - Background jobs for health checks
  - Cached status with expiry
  - Fast path for quick queries (<100ms target)

#### 8. Log Rotation is Not Optional
- **Problem:** Logs grow unbounded, filling disk
- **Solution:**
  - 10MB max log size with automatic rotation
  - 7-day retention with cleanup
  - Log buffering (10x performance improvement)

#### 9. User Experience Matters
- **Problem:** Admin-only commands fail silently for users
- **Solution:**
  - Infer service status from port listening + SSH processes
  - Clear error messages about privilege requirements
  - Non-admin status checks where possible

#### 10. Security is Hard
- **Problem:** SSH credentials in logs, injection vulnerabilities
- **Solution:**
  - Sanitize all inputs (host, user, model names)
  - Never log SecureStrings or keys
  - Validate SSH key permissions
  - Use hashtables not strings for SSH args (prevents injection)

### What Worked Really Well

✅ **Scheduled Tasks as Services** - More flexible than traditional Windows services
✅ **ProgramData for Service Files** - Proper separation of user/system data
✅ **Module in Program Files** - System-wide availability for SYSTEM context
✅ **Dual-Key Strategy** - Service key + admin key for testing
✅ **Process Exit Events** - Instant crash detection, faster than polling
✅ **Network Wait Loop** - Simple but effective boot reliability
✅ **Event Log Integration** - Windows-native diagnostics
✅ **Startup Debug Log** - Critical for troubleshooting boot issues

### What Didn't Work (Don't Repeat)

❌ **Background Jobs** - Too slow, removed AsJob parameter
❌ **Hardcoded IPs** - Security risk, removed fallback IPs
❌ **Blocking Status Checks** - Need async implementation
❌ **Single-Port Design** - Can't handle multi-service scenarios
❌ **Tight Coupling** - Ollama API calls mixed with tunnel management

## TunnelMonitor Architecture - The New Design

### Core Principles

1. **Service Abstraction** - Services are first-class objects with independent lifecycles
2. **Health Check Pluggability** - Each service defines its own health check strategy
3. **Configuration Flexibility** - YAML/JSON configs for complex multi-service setups
4. **Zero Coupling** - No service-specific code in core module
5. **Backward Compatibility** - Simple configs work like OllamaTunnelMonitor

### Service Abstraction Layer

Each service is defined as:

```powershell
@{
    Name = "Ollama"
    LocalPort = 11434
    RemotePort = 11434
    RemoteHost = "localhost"  # On remote server

    # Health check configuration
    HealthCheck = @{
        Type = "HTTP"  # HTTP, TCP, Custom
        Endpoint = "/api/version"
        Timeout = 5000  # ms
        Interval = 60  # seconds
        SuccessThreshold = 1
        FailureThreshold = 3
    }

    # Optional: Custom health check function
    CustomHealthCheck = $null  # ScriptBlock for custom checks

    # Optional: Service-specific environment variables
    EnvironmentVariables = @{
        "OLLAMA_API_URL" = "http://localhost:11434"
    }
}
```

### Multi-Service Configuration Example

```powershell
Set-TunnelConfiguration -Services @(
    @{
        Name = "Ollama"
        LocalPort = 11434
        RemotePort = 11434
        HealthCheck = @{ Type = "HTTP"; Endpoint = "/api/version" }
    },
    @{
        Name = "VisionAPI"
        LocalPort = 5000
        RemotePort = 5000
        HealthCheck = @{ Type = "HTTP"; Endpoint = "/health" }
    },
    @{
        Name = "Samba"
        LocalPort = 445
        RemotePort = 445
        HealthCheck = @{ Type = "TCP" }  # Just check port
    },
    @{
        Name = "Jupyter"
        LocalPort = 8888
        RemotePort = 8888
        HealthCheck = @{ Type = "HTTP"; Endpoint = "/" }
    }
) -SSHHost "server.example.com" -SSHUser "user" -SSHKeyPath "~/.ssh/id_rsa"
```

### Health Check System

**Built-in Health Check Types:**

1. **TCP** - Just verify port is listening (fastest)
2. **HTTP** - GET request to endpoint, check status code
3. **HTTPS** - Same as HTTP with TLS
4. **Custom** - User-provided ScriptBlock

**Health Check State Machine:**

```
Unknown → Checking → Healthy
                   → Degraded (intermittent failures)
                   → Unhealthy (consecutive failures)
                   → Failed (max failures exceeded)
```

**Per-Service Recovery:**

- Each service has independent failure counters
- Service-specific restart logic
- SSH tunnel restart only if all services fail
- Circuit breaker pattern per service

### File Structure

```
TunnelMonitor/
├── src/
│   ├── TunnelMonitor.psd1          # Main manifest
│   ├── TunnelMonitor.psm1          # Core tunnel manager
│   ├── Classes/
│   │   ├── ServiceDefinition.ps1   # Service abstraction
│   │   ├── HealthCheck.ps1         # Health check engine
│   │   └── TunnelManager.ps1       # Tunnel lifecycle
│   └── HealthChecks/
│       ├── TCPHealthCheck.ps1
│       ├── HTTPHealthCheck.ps1
│       └── CustomHealthCheck.ps1
├── examples/
│   ├── ollama-only.ps1             # Simple single-service (backward compat)
│   ├── multi-service.ps1           # Full multi-service example
│   └── custom-health.ps1           # Custom health check example
└── tests/
    └── TunnelMonitor.Tests.ps1     # Pester tests
```

## Ollama-Specific Code → OllamaTools Module

### Functions Moving to OllamaTools

**From OllamaTunnelMonitor.psm1:**

1. ✂️ `Get-OllamaModels` - Model discovery and categorization
2. ✂️ `Export-ModelEnvironmentVariables` - Ollama env vars
3. ✂️ `Get-RemoteGPUStatus` - NVIDIA GPU monitoring
4. ✂️ `$script:DiscoveredModels` - Model state management
5. ✂️ All Ollama API interactions (lines 784, 1027-1029)

**What OllamaTools Becomes:**

A **companion module** that uses TunnelMonitor as a foundation:

```powershell
# OllamaTools.psm1 - Ollama-specific utilities
Import-Module TunnelMonitor -RequiredVersion 1.0

function Install-OllamaService {
    # Wrapper around TunnelMonitor with Ollama defaults
    $ollamaService = @{
        Name = "Ollama"
        LocalPort = 11434
        RemotePort = 11434
        HealthCheck = @{
            Type = "Custom"
            ScriptBlock = { Test-OllamaAPI }
        }
    }

    Install-TunnelService -Services @($ollamaService) @PSBoundParameters

    # Ollama-specific post-install
    Initialize-OllamaModels
}

function Get-OllamaModels { ... }  # Moved from TunnelMonitor
function Export-ModelEnvironmentVariables { ... }
function Get-RemoteGPUStatus { ... }
function Test-OllamaAPI { ... }  # Custom health check
```

### Functions Staying in TunnelMonitor (Generalized)

1. ✅ `Install-TunnelService` - Windows service installation (generalized)
2. ✅ `Start-TunnelService` - Multi-service tunnel manager
3. ✅ `Stop-TunnelService` - Graceful shutdown
4. ✅ `Start-ManagedSSHTunnel` - Multi-port SSH tunnel (refactored)
5. ✅ `Stop-ManagedSSHTunnel` - Tunnel cleanup
6. ✅ `Set-TunnelConfiguration` - Multi-service config (refactored)
7. ✅ `Get-TunnelConfiguration` - Config retrieval
8. ✅ `Get-TunnelStatus` - Multi-service status (refactored)
9. ✅ `Write-Log` - Logging infrastructure
10. ✅ `Get-SSHExecutablePath` - SSH binary resolution
11. ✅ `Test-AdminPrivileges` - Helper function
12. ✅ `Test-SSHKeyPermissions` - Security validation
13. ✅ `Get-ExistingSSHTunnel` - Process discovery (multi-port aware)

### New Functions for TunnelMonitor

1. 🆕 `New-ServiceDefinition` - Create service config objects
2. 🆕 `Test-ServiceHealth` - Run health checks
3. 🆕 `Get-ServiceStatus` - Per-service status
4. 🆕 `Restart-Service` - Service-specific restart (not tunnel)
5. 🆕 `Register-HealthCheck` - Add custom health check types
6. 🆕 `Export-TunnelConfiguration` - Save config to file
7. 🆕 `Import-TunnelConfiguration` - Load config from file

## Configuration Management

### Configuration File Format (YAML)

```yaml
# tunnel-config.yml
ssh:
  host: server.example.com
  user: user
  port: 22
  key_path: ~/.ssh/id_rsa

services:
  - name: Ollama
    local_port: 11434
    remote_port: 11434
    remote_host: localhost
    health_check:
      type: HTTP
      endpoint: /api/version
      timeout: 5000
      interval: 60
      failure_threshold: 3
    env_vars:
      OLLAMA_API_URL: http://localhost:11434

  - name: VisionAPI
    local_port: 5000
    remote_port: 5000
    health_check:
      type: HTTP
      endpoint: /health

  - name: Samba
    local_port: 445
    remote_port: 445
    health_check:
      type: TCP

global:
  log_level: Info
  log_retention_days: 7
  restart_on_failure: true
  max_restart_attempts: 5
```

### Backward Compatibility Layer

For users migrating from OllamaTunnelMonitor:

```powershell
# Old way (still works)
Set-TunnelConfiguration -SSHHost "server" -SSHUser "user" -LocalPort 11434 -RemotePort 11434

# Automatically converts to:
Set-TunnelConfiguration -Services @(
    @{
        Name = "Default"
        LocalPort = 11434
        RemotePort = 11434
        HealthCheck = @{ Type = "TCP" }
    }
) -SSHHost "server" -SSHUser "user"
```

## Development Standards

### Critical Rules (From Hard Experience)

1. **Security First** - Sanitize ALL inputs, especially SSH parameters
2. **Windows PATH Assumptions** - Always search standard locations for SSH
3. **SYSTEM Context** - Test as SYSTEM, not just as admin
4. **Network Timing** - Always wait for network at boot
5. **No Hardcoded Secrets** - Use SecureString or Credential Manager
6. **Resource Cleanup** - Always clean up processes, jobs, temp files
7. **Error Handling** - Try/catch/finally for all external calls
8. **Logging** - Debug logs from the start, never log credentials
9. **Testing** - Test sleep/wake scenarios, not just happy path
10. **Documentation** - Update CLAUDE.md with every architectural change

### Testing Requirements

**Must test scenarios:**
- ✅ SSH connection failures (pre-boot, mid-operation, post-sleep)
- ✅ Service-specific failures (one service down, others up)
- ✅ Health check timeouts and retries
- ✅ Multi-service configuration validation
- ✅ Privilege escalation (user → admin → SYSTEM)
- ✅ Network unavailable at boot
- ✅ SSH key permission issues
- ✅ Sleep/wake tunnel recovery
- ✅ Concurrent service failures
- ✅ Configuration file parsing errors

### Code Organization

**Classes (PowerShell 5.1+ compatible):**

```powershell
# ServiceDefinition.ps1
class ServiceDefinition {
    [string]$Name
    [int]$LocalPort
    [int]$RemotePort
    [string]$RemoteHost = "localhost"
    [hashtable]$HealthCheck
    [hashtable]$EnvironmentVariables = @{}
    [ServiceStatus]$Status = [ServiceStatus]::Unknown
    [int]$ConsecutiveFailures = 0
    [datetime]$LastHealthCheck

    ServiceDefinition([hashtable]$Config) {
        $this.Name = $Config.Name
        $this.LocalPort = $Config.LocalPort
        $this.RemotePort = $Config.RemotePort
        # ... validation
    }

    [bool] IsHealthy() {
        return $this.Status -eq [ServiceStatus]::Healthy
    }
}

enum ServiceStatus {
    Unknown
    Starting
    Healthy
    Degraded
    Unhealthy
    Failed
}
```

### Performance Targets

- **Quick Status Check:** <50ms (cached, TCP-only)
- **Full Status Check:** <500ms (all services, includes HTTP)
- **Service Restart:** <10 seconds (graceful)
- **Boot to Operational:** <120 seconds (including network wait)
- **Memory Usage:** <50MB (module + service script)
- **Log Rotation:** Automatic at 10MB, keep 7 days

## Migration Path

### Phase 1: Fork and Refactor (Current)
- ✅ Clone OllamaTunnelMonitor → TunnelMonitor
- ✅ Write CLAUDE.md (this document)
- ⏳ Identify Ollama-specific code
- ⏳ Design service abstraction layer
- ⏳ Create migration plan

### Phase 2: Core Refactoring
- Implement ServiceDefinition class
- Implement HealthCheck engine
- Refactor Start-ManagedSSHTunnel for multi-port
- Refactor Get-TunnelStatus for multi-service
- Add YAML configuration support
- Add backward compatibility layer

### Phase 3: Extract OllamaTools
- Move Ollama functions to OllamaTools
- Create OllamaTools wrapper module
- Test both modules independently
- Update documentation

### Phase 4: Testing & Polish
- Pester test suite
- Integration tests with real SSH
- Sleep/wake testing
- Multi-service scenarios
- Performance benchmarking

### Phase 5: Release
- TunnelMonitor 1.0.0 (general-purpose)
- OllamaTools 2.0.0 (depends on TunnelMonitor)
- Migration guide for OllamaTunnelMonitor users
- Deprecation notice for OllamaTunnelMonitor

## Git Commit Standards

Same as OllamaTunnelMonitor - use component-specific commits:

```
feat(ServiceDefinition): Add multi-service abstraction layer

[ServiceDefinition] NEW: Service definition class
[ServiceStatus] NEW: Service status enumeration
[New-ServiceDefinition] NEW: Service factory function
[Test-ServiceHealth] NEW: Health check orchestrator
```

**Types:** feat, fix, refactor, perf, test, docs, style, chore, build, ci
**Actions:** NEW, MODIFIED, REMOVED, RENAMED, MOVED, FIXED, REFACTORED, DEPRECATED

## Example Configurations

### Example 1: Simple Ollama (Backward Compatible)

```powershell
# Exactly like OllamaTunnelMonitor
Set-TunnelConfiguration -SSHHost "myserver.com" -SSHUser "user" -LocalPort 11434 -RemotePort 11434
Install-TunnelService -StartNow
```

### Example 2: Multi-Service Development Stack

```powershell
$services = @(
    @{ Name = "Ollama"; LocalPort = 11434; RemotePort = 11434;
       HealthCheck = @{ Type = "HTTP"; Endpoint = "/api/version" } },
    @{ Name = "PostgreSQL"; LocalPort = 5432; RemotePort = 5432;
       HealthCheck = @{ Type = "TCP" } },
    @{ Name = "Redis"; LocalPort = 6379; RemotePort = 6379;
       HealthCheck = @{ Type = "TCP" } },
    @{ Name = "Jupyter"; LocalPort = 8888; RemotePort = 8888;
       HealthCheck = @{ Type = "HTTP"; Endpoint = "/api" } }
)

Set-TunnelConfiguration -Services $services -SSHHost "dev-server" -SSHUser "dev"
Install-TunnelService -StartNow
```

### Example 3: Custom Health Check

```powershell
$visionService = @{
    Name = "VisionAPI"
    LocalPort = 5000
    RemotePort = 5000
    HealthCheck = @{
        Type = "Custom"
        ScriptBlock = {
            param($Service)

            try {
                $response = Invoke-RestMethod "http://localhost:$($Service.LocalPort)/models" -TimeoutSec 2
                return $response.models.Count -gt 0
            }
            catch {
                return $false
            }
        }
    }
}

Set-TunnelConfiguration -Services @($visionService) -SSHHost "vision-server" -SSHUser "ml"
```

## Known Issues from OllamaTunnelMonitor (To Fix)

### Critical (Must Fix)
1. ❌ **Async Health Checks** - Currently blocking, need background jobs
2. ❌ **Resource Leaks** - Background jobs not always cleaned up
3. ❌ **No Circuit Breaker** - Can overwhelm failing services with checks
4. ❌ **Single SSH Connection** - No multiplexing support

### Important (Should Fix)
1. ⚠️ **Config Validation** - No schema validation for service configs
2. ⚠️ **Rate Limiting** - No protection against check storms
3. ⚠️ **Metrics Export** - No Prometheus/telemetry support
4. ⚠️ **Graceful Degradation** - All-or-nothing tunnel restart

### Nice to Have (Future)
1. 💡 **SSH Multiplexing** - Single master connection, multiple tunnels
2. 💡 **WebSocket Status** - Real-time status updates
3. 💡 **Auto-Discovery** - Detect services on remote host
4. 💡 **Load Balancing** - Multiple tunnels to different hosts

## Success Metrics

**TunnelMonitor is successful if:**

✅ Users can replace 5+ manual SSH commands with one `Install-TunnelService`
✅ Service survives laptop sleep/wake without manual intervention
✅ Individual service failures don't kill entire tunnel
✅ Status checks complete in <100ms for quick queries
✅ Zero credential leaks in logs or event viewer
✅ Works identically for SYSTEM service and user testing
✅ OllamaTunnelMonitor users can migrate with <10 lines of config changes

## Contact & Support

- Architecture questions: Tag with [ARCHITECTURE]
- Security issues: Report privately first
- Performance benchmarks: Include in issue
- Multi-service scenarios: Provide config examples

## Notes for AI Assistants

When working on TunnelMonitor:

1. **This is a refactor, not a rewrite** - Preserve working code from OllamaTunnelMonitor
2. **Learn from past mistakes** - Reference the "Lessons Learned" section
3. **Security is critical** - This module handles SSH credentials
4. **Test as SYSTEM** - Most bugs appear in SYSTEM context, not user
5. **Multi-service is the goal** - Every design decision should support multiple services
6. **Backward compatibility matters** - OllamaTunnelMonitor users exist

## Current State: Architecture Design

**What exists:**
- ✅ Forked codebase from OllamaTunnelMonitor v1.7.0
- ✅ Comprehensive architecture design (this document)
- ✅ Lessons learned documented
- ✅ Migration path defined

**Next steps:**
1. Implement ServiceDefinition class
2. Refactor Start-ManagedSSHTunnel for multi-port
3. Implement health check engine
4. Extract Ollama code to OllamaTools
5. Create test suite
