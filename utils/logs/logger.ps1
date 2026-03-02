<#
.SYNOPSIS
Utilidad centralizada para imprimir logs en pantalla.
Uso: . "ruta\a\logger.ps1"
#>

function Write-LogInfo ([string]$Message) {
    $Stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[INFO] $Stamp - $Message" -ForegroundColor Cyan
}

function Write-LogSuccess ([string]$Message) {
    $Stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[OK]   $Stamp - $Message" -ForegroundColor Green
}

function Write-LogWarn ([string]$Message) {
    $Stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[WARN] $Stamp - $Message" -ForegroundColor Yellow
}

function Write-LogError ([string]$Message) {
    $Stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[FAIL] $Stamp - $Message" -ForegroundColor Red
    throw "[FAIL] $Stamp - $Message"
}
