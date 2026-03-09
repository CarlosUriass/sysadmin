[cmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [Alias("p")]
    [string]$Port,

    [switch]$Help
)

if ($Help) {
    Write-Host "Uso: .\kill_port_process.ps1 -Port <numero_puerto>"
    exit 0
}

# Buscamos procesos consumiendo TCP
$tcpConnections = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
# Buscamos procesos consumiendo UDP
$udpConnections = Get-NetUDPEndpoint -LocalPort $Port -ErrorAction SilentlyContinue

$foundProcesses = $false

if ($tcpConnections) {
    foreach ($conn in $tcpConnections) {
        $pidNum = $conn.OwningProcess
        if ($pidNum -gt 0) {
            Write-Host "Deteniendo proceso TCP con PID $pidNum bloqueando el puerto $Port"
            Stop-Process -Id $pidNum -Force -ErrorAction SilentlyContinue
            $foundProcesses = $true
        }
    }
}

if ($udpConnections) {
    foreach ($conn in $udpConnections) {
        $pidNum = $conn.OwningProcess
        if ($pidNum -gt 0) {
            Write-Host "Deteniendo proceso UDP con PID $pidNum bloqueando el puerto $Port"
            Stop-Process -Id $pidNum -Force -ErrorAction SilentlyContinue
            $foundProcesses = $true
        }
    }
}

if ($foundProcesses) {
    Write-Host "Procesos del puerto $Port detenidos con éxito."
    exit 0
} else {
    Write-Host "No se encontraron procesos activos usando el puerto $Port."
    exit 1
}
