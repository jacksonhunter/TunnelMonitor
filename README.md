# TunnelMonitor

**General-purpose SSH tunnel manager with multi-service support, health monitoring, and Windows service integration.**

## Status: 🚧 Architecture Design Phase

This project is a **ground-up refactor** of [OllamaTunnelMonitor](../OllamaTunnelMonitor) to support multiple services with independent health checks.

**Current Version:** 1.0.0-alpha
**Parent Project:** OllamaTunnelMonitor v1.7.0

## What's Different from OllamaTunnelMonitor?

| Feature | OllamaTunnelMonitor | TunnelMonitor |
|---------|---------------------|---------------|
| **Purpose** | Single Ollama tunnel | Multi-service tunnel manager |
| **Ports** | One (11434) | Unlimited |
| **Health Checks** | Ollama API only | Per-service (HTTP/TCP/Custom) |
| **Services** | Hardcoded Ollama | Pluggable service definitions |
| **Config** | Function parameters | YAML/JSON configs |
| **Coupling** | Tight (Ollama API calls in core) | Zero (service-agnostic) |

## Vision

Manage complex multi-service SSH tunnels like this:

```powershell
# Define your entire dev stack
$services = @(
    @{ Name = "Ollama"; LocalPort = 11434; RemotePort = 11434;
       HealthCheck = @{ Type = "HTTP"; Endpoint = "/api/version" } },
    @{ Name = "VisionAPI"; LocalPort = 5000; RemotePort = 5000;
       HealthCheck = @{ Type = "HTTP"; Endpoint = "/health" } },
    @{ Name = "PostgreSQL"; LocalPort = 5432; RemotePort = 5432;
       HealthCheck = @{ Type = "TCP" } },
    @{ Name = "Samba"; LocalPort = 445; RemotePort = 445;
       HealthCheck = @{ Type = "TCP" } }
)

# One command to rule them all
Set-TunnelConfiguration -Services $services -SSHHost "dev-server" -SSHUser "dev"
Install-TunnelService -StartNow

# Independent health monitoring
Get-ServiceStatus  # Shows per-service health

# Service-specific restart (doesn't kill whole tunnel)
Restart-Service -ServiceName "VisionAPI"
```

## Architecture Highlights

### Service Abstraction
Each service is a first-class object with:
- Independent health checks (HTTP, TCP, or custom)
- Per-service failure counters and circuit breakers
- Service-specific environment variables
- Pluggable health check strategies

### Health Check System
- **TCP:** Fast port listening check
- **HTTP:** GET request with status code validation
- **Custom:** User-defined ScriptBlock for complex checks
- **State Machine:** Unknown → Healthy → Degraded → Unhealthy → Failed

### Learned from 7 Versions
- ✅ SYSTEM context SSH key handling
- ✅ Network timing at boot
- ✅ Sleep/wake tunnel recovery
- ✅ Windows-specific SSH gotchas
- ✅ Log rotation and buffering
- ✅ Security hardening
- ✅ Power event integration

## Project Structure

```
TunnelMonitor/
├── src/
│   ├── TunnelMonitor.psd1          # Main manifest
│   ├── TunnelMonitor.psm1          # Core (to be refactored)
│   ├── OllamaTools.psd1            # Ollama-specific companion
│   └── OllamaTools.psm1            # Ollama utilities
├── examples/                        # (To be created)
│   ├── simple-ollama.ps1
│   ├── multi-service.ps1
│   └── custom-health.ps1
├── tests/                           # (To be created)
│   └── TunnelMonitor.Tests.ps1
├── CLAUDE.md                        # Comprehensive architecture doc
└── README.md                        # This file
```

## Current Phase: Architecture & Planning

**Completed:**
- ✅ Forked from OllamaTunnelMonitor v1.7.0
- ✅ Architecture design documented in CLAUDE.md
- ✅ Service abstraction design
- ✅ Health check system design
- ✅ Migration path defined
- ✅ Lessons learned documented

**Next Steps:**
1. Implement `ServiceDefinition` class
2. Refactor `Start-ManagedSSHTunnel` for multi-port
3. Implement health check engine
4. Extract Ollama code to OllamaTools
5. Create Pester test suite
6. Build example configurations

## Relationship with OllamaTools

**TunnelMonitor** = General-purpose tunnel manager (this repo)
**OllamaTools** = Ollama-specific utilities (companion module)

OllamaTools will **depend on** TunnelMonitor:

```powershell
# OllamaTools wraps TunnelMonitor with Ollama defaults
Install-OllamaService  # Uses TunnelMonitor under the hood

# Ollama-specific features stay in OllamaTools
Get-OllamaModels
Export-ModelEnvironmentVariables
Get-RemoteGPUStatus
```

## Backward Compatibility

For OllamaTunnelMonitor users:

```powershell
# Old way (OllamaTunnelMonitor)
Set-TunnelConfiguration -SSHHost "server" -SSHUser "user" -LocalPort 11434

# Still works in TunnelMonitor (converts to single-service config)
Set-TunnelConfiguration -SSHHost "server" -SSHUser "user" -LocalPort 11434
```

## Requirements

- **PowerShell:** 7.1+ (Core edition)
- **OS:** Windows 10/11, Windows Server 2019+
- **SSH Client:** OpenSSH client (built-in on modern Windows)
- **Privileges:** Administrator (for service installation)

## Documentation

- **CLAUDE.md** - Comprehensive architecture, lessons learned, development guidelines
- **README.md** - This file (project overview)
- **/examples** - Usage examples (to be created)
- **Inline comments** - Function-level documentation

## Contributing

This is currently in **architecture design phase**. Major refactoring in progress.

See `CLAUDE.md` for:
- Lessons learned from OllamaTunnelMonitor
- Detailed architecture design
- Development standards
- Testing requirements
- Migration plan

## License

(To be determined - likely MIT or Apache 2.0)

## Acknowledgments

Built on lessons from **OllamaTunnelMonitor v1.0.0 → v1.7.0**:
- 7 versions of SSH tunnel battle scars
- Windows SYSTEM context hardening
- Sleep/wake recovery patterns
- Security lessons learned the hard way

## Status Updates

**2025-10-21:** Project initialized, architecture designed in CLAUDE.md
**Next Milestone:** ServiceDefinition class implementation

---

**Note:** This is a complete architectural redesign. The current code is from OllamaTunnelMonitor and will be refactored according to the design in CLAUDE.md.
