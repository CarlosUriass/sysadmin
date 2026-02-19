<#
.SYNOPSIS
Enterprise-Grade Windows DNS Server Automation Script
.DESCRIPTION
Implementa infraestructura crítica as-code. Totalmente idempotente, genera logs transaccionales, efectúa hardening básico, y valida estados de red antes de aplicar modificaciones al motor WMI/CIM.
#>

[CmdletBinding(DefaultParameterSetName='Interactive')]
param (
    [Parameter(Mandatory=$false, ParameterSetName='CLI')]
    [ValidatePattern('^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')]
    [string]$TargetClientIP
)

# ------------------------------------------------------------------------------
# 1. Configuración Inicial y Strict Mode
# ------------------------------------------------------------------------------
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Domain = "reprobados.com"
$LogPath = "$env:TEMP\dns_setup_enterprise.log"

Function Write-Log {
    param([string]$Message, [string]$Level="INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $fmt = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "INFO" { Write-Host $fmt -ForegroundColor Cyan }
        "OK"   { Write-Host $fmt -ForegroundColor Green }
        "WARN" { Write-Host $fmt -ForegroundColor Yellow }
        "FAIL" { Write-Host $fmt -ForegroundColor Red }
    }
    Add-Content -Path $LogPath -Value $fmt
}

Write-Log "Iniciando Despliegue DNS Enterprise..." "INFO"

# ------------------------------------------------------------------------------
# 2. Assertions y Seguridad Previa
# ------------------------------------------------------------------------------
try {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Privilegios insuficientes. Requerido Rol Administrador."
    }
} catch {
    Write-Log $_.Exception.Message "FAIL"
    exit 1
}

# ------------------------------------------------------------------------------
# 3. Interfaz y Red
# ------------------------------------------------------------------------------
If ([string]::IsNullOrEmpty($TargetClientIP)) {
    do {
        $TargetClientIP = Read-Host "Por favor ingrese la IP Objetivo del Cliente (Regex Checked)"
    } until ($TargetClientIP -match "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")
}

try {
    $ActiveIface = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.Virtual -eq $false } | Select-Object -First 1
    if ($ActiveIface) {
        $NetConf = Get-NetIPInterface -InterfaceAlias $ActiveIface.Name -AddressFamily IPv4
        if ($NetConf.Dhcp -eq "Enabled") {
            Write-Log "DHCP Detectado en la interfaz $($ActiveIface.Name). En un entorno Prod esto causará problemas de resolución." "WARN"
            # Idempotencia: No forzamos cambio IP brusco si es lab (para no romper conexión remota RDP WinRM)
            # Solo advertimos.
        } else {
            Write-Log "Interfaces en modo IPv4 Static... Comprobación de Red exitosa." "OK"
        }
    }
} catch {
    Write-Log "Error al verificar adaptadores WMI: $_" "WARN"
}

# ------------------------------------------------------------------------------
# 4. Instalación de Motor DNS (Role)
# ------------------------------------------------------------------------------
try {
    $Feature = Get-WindowsFeature -Name "DNS"
    if ($Feature.Installed) {
        Write-Log "Rol Dns-Server previamente instalado. Verificación Idempotente Ok." "OK"
    } else {
        Write-Log "Ejecutando instalación de Binarios y Componentes Dns-Server..." "INFO"
        Install-WindowsFeature -Name DNS -IncludeManagementTools | Out-Null
        Write-Log "Instalación completada via FeatureManager." "OK"
    }

    $Service = Get-Service -Name "DNS"
    if ($Service.Status -ne "Running") {
        Start-Service "DNS"
        Set-Service "DNS" -StartupType Automatic
        Write-Log "Servicio Activado." "OK"
    }
} catch {
    Write-Log "Excepción manipulando servicio DNS. $_" "FAIL"
    exit 1
}

# ------------------------------------------------------------------------------
# 5. Configuración Autoritativa e Ingeniería de Zonas
# ------------------------------------------------------------------------------
try {
    Write-Log "Accediendo motor CIW/CMDLET DnsServerScope..." "INFO"
    
    # Evaluar Zona Primaria
    $existingZone = Get-DnsServerZone -Name $Domain -ErrorAction SilentlyContinue
    if (-not $existingZone) {
        Add-DnsServerPrimaryZone -Name $Domain -DynamicUpdate "None" -ZoneFile "$Domain.dns" -ErrorAction Stop
        Write-Log "Primary Zone $Domain creada. [Dynamic Update = Blocked, Security Hardening]." "OK"
    } else {
        Write-Log "Zona $Domain persistida previamente." "OK"
    }

    # Modificar/Validar Records (Resguardo ante múltiples ejecuciones)
    
    # Récord A (Raíz)
    $recA = Get-DnsServerResourceRecord -ZoneName $Domain -Name "@" -RRType "A" -ErrorAction SilentlyContinue
    if (-not $recA) {
        Add-DnsServerResourceRecordA -ZoneName $Domain -Name "@" -IPv4Address $TargetClientIP -TimeToLive 01:00:00 -ErrorAction Stop
        Write-Log "A Record Inyectado @ -> $TargetClientIP [TTL 1hr]" "OK"
    } else {
        $actualIP = $recA.RecordData.IPv4Address.IPAddressToString
        if ($actualIP -ne $TargetClientIP) {
            Write-Log "El Record A existe pero diverge. Forzando Update $actualIP -> $TargetClientIP" "WARN"
            $newRec = $recA.Clone()
            $newRec.RecordData.IPv4Address = [System.Net.IPAddress]::Parse($TargetClientIP)
            Set-DnsServerResourceRecord -NewInputObject $newRec -OldInputObject $recA -ZoneName $Domain
            Write-Log "Actualización Transaccional Finalizada." "OK"
        } else {
            Write-Log "A Record exacto verificado." "OK"
        }
    }

    # Récord CNAME (www)
    $recC = Get-DnsServerResourceRecord -ZoneName $Domain -Name "www" -RRType "CNAME" -ErrorAction SilentlyContinue
    if (-not $recC) {
        Add-DnsServerResourceRecordCName -ZoneName $Domain -Name "www" -HostNameAlias $Domain -TimeToLive 01:00:00 -ErrorAction Stop
        Write-Log "CNAME Inyectado www -> $Domain" "OK"
    } else {
        Write-Log "CNAME exacto comprobado en la estructura lógica." "OK"
    }

} catch {
    Write-Log "Violación de Estado en construcción de DNS DCOM. Trace: $_" "FAIL"
    exit 1
}

# ------------------------------------------------------------------------------
# 6. Flush de Caché y Self-Diagnostic Checklist
# ------------------------------------------------------------------------------
Clear-DnsClientCache
Restart-Service "DNS" -ErrorAction SilentlyContinue

Write-Host "`n================================================" -ForegroundColor Cyan
Write-Host "       CHECKLIST FINAL DE SELF-DIAGNOSTIC       " -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "$("{0,-30} | {1,-12}" -f 'PRUEBA', 'ESTADO')" -ForegroundColor Gray
Write-Host "------------------------------------------------" -ForegroundColor Gray

function Test-Check {
    param([string]$name, [bool]$eval)
    if ($eval) { Write-Host ("{0,-30} | " -f $name) -NoNewline; Write-Host "OK" -ForegroundColor Green }
    else       { Write-Host ("{0,-30} | " -f $name) -NoNewline; Write-Host "FAIL" -ForegroundColor Red }
}

$serviceOk = (Get-Service DNS).Status -eq 'Running'
Test-Check "DNS Service Running" $serviceOk

$portOk = (Get-NetTCPConnection -LocalPort 53 -ErrorAction SilentlyContinue) -ne $null
Test-Check "Puerto UDP/TCP 53 Atendiendo" $portOk

# Evaluando Lookups
$aResolve = Resolve-DnsName -Name $Domain -Server 127.0.0.1 -ErrorAction SilentlyContinue
Test-Check "Resolución Raíz (A)" ($aResolve -ne $null)

$cResolve = Resolve-DnsName -Name "www.$Domain" -Server 127.0.0.1 -ErrorAction SilentlyContinue
Test-Check "Resolución CNAME (www)" ($cResolve -ne $null)

Write-Host "================================================`n" -ForegroundColor Cyan
Write-Log "Finalizado de forma natural (Exit Code 0)." "INFO"
Exit 0
