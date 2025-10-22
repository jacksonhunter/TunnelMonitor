# Multi-Service SSH Tunnel Example
# This example demonstrates how to configure TunnelMonitor to forward multiple services
# through a single SSH tunnel connection.

Import-Module TunnelMonitor

# Example 1: Simple multi-port forwarding (same local and remote ports)
# -------------------------------------------------------------------------
Write-Host "Example 1: Simple multi-port forwarding" -ForegroundColor Cyan

Set-TunnelConfiguration `
    -SSHHost "myserver.example.com" `
    -SSHUser "user" `
    -SSHKeyPath "~/.ssh/id_rsa" `
    -LocalPort 11434 `
    -RemotePort 11434 `
    -AdditionalServices @{
        VisionAPI = 5000
        Samba = 445
        Jupyter = 8888
    }

# This will create an SSH tunnel with the following port forwards:
# -L 11434:localhost:11434  (Main service - Ollama)
# -L 5000:localhost:5000    (VisionAPI)
# -L 445:localhost:445      (Samba)
# -L 8888:localhost:8888    (Jupyter)


# Example 2: Advanced multi-service with different local/remote ports
# -------------------------------------------------------------------------
Write-Host "`nExample 2: Advanced configuration with different ports" -ForegroundColor Cyan

Set-TunnelConfiguration `
    -SSHHost "myserver.example.com" `
    -SSHUser "user" `
    -LocalPort 11434 `
    -RemotePort 11434 `
    -AdditionalServices @{
        VisionAPI = @{
            LocalPort = 5000
            RemotePort = 5001
            RemoteHost = "192.168.1.100"  # Different remote host
        }
        Database = @{
            LocalPort = 5432
            RemotePort = 5432
        }
    }


# Example 3: Install and start the service
# -------------------------------------------------------------------------
Write-Host "`nExample 3: Install as Windows service" -ForegroundColor Cyan

# This requires administrative privileges
# Install-TunnelService -StartNow


# Example 4: Check which ports are listening
# -------------------------------------------------------------------------
Write-Host "`nExample 4: Test all forwarded ports" -ForegroundColor Cyan

# Quick TCP connectivity check for all services
Test-TunnelPorts

# Sample output:
# ServiceName  Port  Listening  ResponseTimeMs
# -----------  ----  ---------  --------------
# Main         11434 True       12
# VisionAPI    5000  True       8
# Samba        445   False      -1
# Jupyter      8888  True       15


# Example 5: Get comprehensive status including additional services
# -------------------------------------------------------------------------
Write-Host "`nExample 5: Get full tunnel status" -ForegroundColor Cyan

$status = Get-TunnelStatus -Check Full

Write-Host "Overall Status: $($status.Status)"
Write-Host "Main Service (Port $($status.PortListening)): $($status.PortListening ? 'Listening' : 'Not Listening')"

if ($status.AdditionalServices.Count -gt 0) {
    Write-Host "`nAdditional Services:"
    foreach ($svc in $status.AdditionalServices) {
        $listening = if ($svc.Listening) { "Listening" } else { "Not Listening" }
        Write-Host "  $($svc.Name) (Port $($svc.Port)): $listening"
    }
}


# Example 6: Filter to check specific services
# -------------------------------------------------------------------------
Write-Host "`nExample 6: Check only specific services" -ForegroundColor Cyan

# Show only services that are NOT listening
$failedServices = Test-TunnelPorts | Where-Object {-not $_.Listening}

if ($failedServices) {
    Write-Host "WARNING: The following services are not responding:" -ForegroundColor Yellow
    $failedServices | Format-Table -AutoSize
}
else {
    Write-Host "All services are responding!" -ForegroundColor Green
}


# Example 7: Your use case - Vision API, Ollama, and Samba
# -------------------------------------------------------------------------
Write-Host "`nExample 7: Your specific use case" -ForegroundColor Cyan

Set-TunnelConfiguration `
    -SSHHost "user@your-server.com" `
    -SSHUser "user" `
    -LocalPort 11434 `
    -RemotePort 11434 `
    -AdditionalServices @{
        VisionAPI = 5000
        Samba = 445
    }

# Install and start
# Install-TunnelService -StartNow

# Quick check
Write-Host "`nPort Status:"
Test-TunnelPorts | Format-Table -AutoSize

# Full status
Write-Host "`nFull Status:"
Get-TunnelStatus -Check Full
