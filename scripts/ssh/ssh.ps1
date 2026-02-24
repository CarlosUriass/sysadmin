<#
.SYNOPSIS
Instala, configura y gestiona el servicio SSH en Windows Server / Windows 10+
.DESCRIPTION
Usa las utilidades compartidas para permisos e instalacion. Configura reglas de Firewall para el puerto 22.
#>

[CmdletBinding(DefaultParameterSetName = 'Full')]
param(
    [Parameter(ParameterSetName = 'Install')]
    [Alias('i')]
    [switch]$Install,

    [Parameter(ParameterSetName = 'Enable')]
    [Alias('e')]
    [switch]$Enable,

    [Parameter(ParameterSetName = 'Disable')]
    [Alias('d')]
    [switch]$Disable,

    [Parameter(ParameterSetName = 'Status')]
    [Alias('s')]
    [switch]$Status,

    [Parameter(ParameterSetName = 'Help')]
    [Alias('h')]
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Utils ---

function Verificar-Administrador {
    & "$PSScriptRoot\..\..\utils\ps1\permissions.ps1" -CheckAdmin
    if ($LASTEXITCODE -ne 0) { exit 1 }
}

# --- Instalar ---

function Instalar-SSH {
    Write-Host "=== INSTALACION SSH ==="

    # Windows Server: OpenSSH es un Feature
    $cap = Get-WindowsCapability -Online -Name "OpenSSH.Server*" -ErrorAction SilentlyContinue
    if ($cap -and $cap.State -eq "Installed") {
        Write-Host "ok: OpenSSH Server ya instalado"
        return
    }

    # Intentar como Capability (Win10/11/Server 2019+)
    if ($cap) {
        Write-Host "info: instalando OpenSSH Server como Capability..."
        Add-WindowsCapability -Online -Name $cap.Name -ErrorAction SilentlyContinue | Out-Null
        if ($?) {
            Write-Host "ok: OpenSSH Server instalado"
            return
        }
    }

    # Fallback: WindowsFeature (Server con RSAT)
    try {
        & "$PSScriptRoot\..\..\utils\ps1\install_feature.ps1" -FeatureName "OpenSSH-Server" -ErrorAction SilentlyContinue
    } catch {
        Write-Host "alerta: no se pudo instalar via Feature. Intente manualmente."
    }
}

# --- Habilitar y arrancar ---

function Habilitar-SSH {
    Write-Host "=== HABILITANDO SSH ==="
    $svc = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Host "error: servicio sshd no encontrado. Instale primero con -Install"
        return
    }

    Set-Service -Name sshd -StartupType Automatic
    Start-Service -Name sshd -ErrorAction SilentlyContinue
    Write-Host "ok: servicio sshd habilitado en el boot y arrancado"
}

# --- Firewall ---

function Configurar-Firewall {
    Write-Host "=== FIREWALL ==="
    $rule = Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue
    if ($rule) {
        if ($rule.Enabled -eq 'True') {
            Write-Host "ok: regla de firewall para SSH ya existe y esta habilitada"
        } else {
            Enable-NetFirewallRule -Name "OpenSSH-Server-In-TCP"
            Write-Host "ok: regla de firewall para SSH re-habilitada"
        }
    } else {
        New-NetFirewallRule -Name "OpenSSH-Server-In-TCP" `
            -DisplayName "OpenSSH SSH Server (sshd) Puerto 22" `
            -Enabled True `
            -Direction Inbound `
            -Protocol TCP `
            -Action Allow `
            -LocalPort 22 `
            -ErrorAction SilentlyContinue | Out-Null
        Write-Host "ok: regla de firewall creada para puerto 22/TCP"
    }
}

# --- Estado ---

function Mostrar-Estado {
    Write-Host ""
    Write-Host "=== ESTADO SSH ==="
    $svc = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Host "servicio: NO ENCONTRADO (no instalado)"
        return
    }

    if ($svc.Status -eq 'Running') { Write-Host "servicio: ACTIVO" }
    else                           { Write-Host "servicio: INACTIVO ($($svc.Status))" }

    if ($svc.StartType -eq 'Automatic') { Write-Host "boot: HABILITADO" }
    else                                 { Write-Host "boot: DESHABILITADO ($($svc.StartType))" }

    $rule = Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue
    if ($rule -and $rule.Enabled -eq 'True') { Write-Host "firewall: PERMITIDO (puerto 22)" }
    else                                      { Write-Host "firewall: BLOQUEADO o sin regla" }
}

# --- Desactivar ---

function Desactivar-SSH {
    Write-Host "=== DESACTIVANDO SSH ==="
    $svc = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if ($svc) {
        Stop-Service -Name sshd -Force -ErrorAction SilentlyContinue
        Set-Service -Name sshd -StartupType Disabled
        Write-Host "ok: servicio sshd detenido y deshabilitado"
    } else {
        Write-Host "info: servicio sshd no encontrado"
    }

    # Deshabilitar regla de firewall
    Disable-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue
    Write-Host "ok: regla de firewall deshabilitada"
}

# --- Ayuda ---

function Mostrar-Ayuda {
    Write-Host "uso: .\ssh.ps1 [opcion]"
    Write-Host "  -i  instalar    -e  habilitar    -d  desactivar    -s  estado    -h  ayuda"
    Write-Host "  sin opciones = flujo completo (instalar + habilitar + firewall)"
}

# --- Main ---

Write-Host "=== SSH Server - Windows ==="

if ($Help)   { Mostrar-Ayuda; exit 0 }
if ($Status) { Mostrar-Estado; exit 0 }

Verificar-Administrador

if ($Install)       { Instalar-SSH }
elseif ($Enable)    { Habilitar-SSH; Configurar-Firewall }
elseif ($Disable)   { Desactivar-SSH }
else                { Instalar-SSH; Habilitar-SSH; Configurar-Firewall; Mostrar-Estado }
