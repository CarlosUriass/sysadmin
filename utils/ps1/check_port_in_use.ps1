[cmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [Alias("p")]
    [string]$Port,

    [switch]$Help
)

. "$PSScriptRoot\..\logs\logger.ps1"

if ($Help) {
    Write-LogInfo "Uso: .\check_port_in_use.ps1 -Port <numero_puerto>"
    exit 0
}

# Verificamos si hay alguna conexión local usando ese puerto
$connections = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue

if ($connections) {
    Write-LogWarn "El puerto $Port está en uso."
    exit 0
} else {
    # También revisamos los bindings de puertos UDP por si acaso
    $udpConnections = Get-NetUDPEndpoint -LocalPort $Port -ErrorAction SilentlyContinue
    if ($udpConnections) {
        Write-LogWarn "El puerto UDP $Port está en uso."
        exit 0
    }

    Write-LogInfo "El puerto $Port no está en uso."
    exit 1
}
