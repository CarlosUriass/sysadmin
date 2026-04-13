<#
.SYNOPSIS
Une un cliente Windows al dominio de Active Directory.
.DESCRIPTION
Solicita el nombre del dominio y credenciales de administrador,
luego ejecuta Add-Computer para unirse al dominio y reinicia.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$DomainName,

    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ==============================================================================
# LOGGING & UTILIDADES
# ==============================================================================
. "$PSScriptRoot\..\..\utils\logs\logger.ps1"

function Verificar-Administrador {
    & "$PSScriptRoot\..\..\utils\ps1\permissions.ps1" -CheckAdmin
    if ($LASTEXITCODE -ne 0) {
        Write-LogError "Ejecutar como administrador."
    }
}

# ==============================================================================
# AYUDA
# ==============================================================================
if ($Help) {
    Write-Host "uso: .\join_domain_windows.ps1 [-DomainName <dominio>]"
    Write-Host "  -DomainName   nombre del dominio (ej. laboratorio.local)"
    Write-Host "  -Help         muestra este mensaje"
    exit 0
}

# ==============================================================================
# MAIN
# ==============================================================================
Write-Host "=== Union al Dominio — Cliente Windows ===" -ForegroundColor White

Verificar-Administrador

# Solicitar dominio si no se proporciono
if ([string]::IsNullOrWhiteSpace($DomainName)) {
    do {
        $DomainName = Read-Host "nombre del dominio (ej. laboratorio.local)"
    } until (-not [string]::IsNullOrWhiteSpace($DomainName))
}

# Verificar si ya esta en el dominio
$currentDomain = (Get-WmiObject Win32_ComputerSystem).Domain
if ($currentDomain -eq $DomainName) {
    Write-LogInfo "este equipo ya esta unido al dominio $DomainName"
    exit 0
}

# Solicitar credenciales de administrador del dominio
Write-LogInfo "solicite credenciales de administrador del dominio $DomainName"
$credential = Get-Credential -Message "Credenciales de administrador para $DomainName"

# Unirse al dominio
Write-LogInfo "uniendo equipo al dominio $DomainName ..."

try {
    Add-Computer -DomainName $DomainName -Credential $credential -Force -ErrorAction Stop
    Write-LogSuccess "equipo unido al dominio $DomainName"
} catch {
    Write-LogError "error al unirse al dominio: $_"
}

# Preguntar si reiniciar ahora
$restart = Read-Host "reiniciar ahora? [S/N]"
if ($restart -match '^[Ss]$') {
    Write-LogInfo "reiniciando equipo..."
    Restart-Computer -Force
} else {
    Write-LogWarn "el equipo debe reiniciarse para completar la union al dominio"
}
