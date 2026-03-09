[cmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [Alias("p")]
    [string]$Port,

    [switch]$Help
)

if ($Help) {
    Write-Host "Uso: .\validate_port.ps1 -Port <numero_puerto>"
    exit 0
}

# Verificar que sea numérico
if ($Port -notmatch '^\d+$') {
    exit 1
}

$portValue = [int]$Port

# Verificar rango
if ($portValue -lt 1 -or $portValue -gt 65535) {
    exit 1
}

# Verificar puertos reservados (1-1023)
if ($portValue -ge 1 -and $portValue -le 1023) {
    exit 1
}

exit 0
