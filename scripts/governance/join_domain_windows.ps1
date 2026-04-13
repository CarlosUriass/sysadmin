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

    [switch]$Leave,

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
    Write-Host "uso: .\join_domain_windows.ps1 [-DomainName <dominio>] [-Leave]"
    Write-Host "  -DomainName   nombre del dominio (ej. laboratorio.local)"
    Write-Host "  -Leave        salir del dominio y volver a WORKGROUP"
    Write-Host "  -Help         muestra este mensaje"
    exit 0
}

# ==============================================================================
# MAIN
# ==============================================================================
Write-Host "=== Union al Dominio - Cliente Windows ===" -ForegroundColor White

Verificar-Administrador

# ==============================================================================
# SALIR DEL DOMINIO
# ==============================================================================
if ($Leave) {
    Write-Host "=== Salir del Dominio ==="  -ForegroundColor White
    $currentDomain = (Get-WmiObject Win32_ComputerSystem).Domain
    if ($currentDomain -eq 'WORKGROUP') {
        Write-LogInfo "este equipo no esta unido a ningun dominio"
        exit 0
    }
    Write-LogInfo "dominio actual: $currentDomain"
    Write-LogInfo "solicite credenciales de administrador del dominio"
    $cred = Get-Credential -Message "Credenciales de admin para salir de $currentDomain"
    try {
        Remove-Computer -UnjoinDomainCredential $cred -WorkgroupName "WORKGROUP" -Force -ErrorAction Stop
        Write-LogSuccess "equipo removido del dominio $currentDomain"
        Write-LogInfo "reiniciando equipo..."
        Restart-Computer -Force
    } catch {
        Write-LogError "error al salir del dominio: $_"
    }
    exit 0
}

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

# --- Configurar DNS para que apunte al Domain Controller ---
Write-LogInfo "configurando DNS del cliente para resolver el dominio..."
$serverIP = Read-Host "IP del Domain Controller (servidor)"

# Validar IP
& "$PSScriptRoot\..\..\utils\ps1\validate_ip.ps1" -IP $serverIP
if ($LASTEXITCODE -ne 0) {
    Write-LogError "IP invalida: $serverIP"
}

# Detectar interfaz activa en la misma subred
$bestIface = $null
$adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
foreach ($a in $adapters) {
    $ip = Get-NetIPAddress -InterfaceAlias $a.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($ip) {
        $clientPrefix = ($ip.IPAddress.Split('.')[0..2]) -join '.'
        $serverPrefix = ($serverIP.Split('.')[0..2]) -join '.'
        if ($clientPrefix -eq $serverPrefix) {
            $bestIface = $a.Name
            break
        }
    }
}

if (-not $bestIface) {
    # Si no hay match de subred, usar la primera interfaz activa
    $bestIface = ($adapters | Select-Object -First 1).Name
    Write-LogWarn "no se detecto interfaz en la misma subred, usando: $bestIface"
}

Write-LogInfo "configurando DNS en interfaz: $bestIface -> $serverIP"
Set-DnsClientServerAddress -InterfaceAlias $bestIface -ServerAddresses $serverIP

# Verificar resolusion del dominio
Write-LogInfo "verificando resolucion de $DomainName ..."
$resolved = Resolve-DnsName -Name $DomainName -ErrorAction SilentlyContinue
if ($resolved) {
    Write-LogSuccess "dominio $DomainName resuelto correctamente"
} else {
    Write-LogError "no se pudo resolver $DomainName. Verifique la red y que el DC este activo."
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
