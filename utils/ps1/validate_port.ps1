[cmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [Alias("p")]
    [string]$Port,

    [switch]$Help
)

. "$PSScriptRoot\..\logs\logger.ps1"

if ($Help) {
    Write-LogInfo "Uso: .\validate_port.ps1 -Port <numero_puerto>"
    exit 0
}

# Verificar que sea numérico
if ($Port -notmatch '^\d+$') {
    Write-LogError "El puerto $Port no es un número válido."
}

$portValue = [int]$Port

# Verificar rango
if ($portValue -lt 1 -or $portValue -gt 65535) {
    Write-LogError "El puerto $Port está fuera de rango (1-65535)."
}

# Verificar puertos reservados (1-1023)
if ($portValue -ge 1 -and $portValue -le 1023) {
    Write-LogError "El puerto $Port es reservado (1-1023)."
}

Write-LogSuccess "El puerto $Port es válido."
exit 0
