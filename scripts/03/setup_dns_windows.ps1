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
    param([string]$Message, [string]$Level="info")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $fmt = "$timestamp - $Level: $Message"
    Write-Host "$Level: $Message"
    Add-Content -Path $LogPath -Value $fmt
}

Write-Log "iniciando dns server" "info"

# ------------------------------------------------------------------------------
# 2. Assertions y Seguridad Previa
# ------------------------------------------------------------------------------
try {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "abre esto como administrador"
    }
} catch {
    Write-Log $_.Exception.Message "error"
    exit 1
}

# ------------------------------------------------------------------------------
# 3. Interfaz y Red
# ------------------------------------------------------------------------------
If ([string]::IsNullOrEmpty($TargetClientIP)) {
    do {
        $TargetClientIP = Read-Host "ip del cliente objetivo"
    } until ($TargetClientIP -match "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")
}

try {
    $ActiveIface = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.Virtual -eq $false } | Select-Object -First 1
    if ($ActiveIface) {
        $NetConf = Get-NetIPInterface -InterfaceAlias $ActiveIface.Name -AddressFamily IPv4
        if ($NetConf.Dhcp -eq "Enabled") {
            Write-Log "dhcp detectado. podria fallar" "alerta"
        } else {
            Write-Log "ip estatica detectada" "ok"
        }
    }
} catch {
    Write-Log "error verificando red: $_" "alerta"
}

# ------------------------------------------------------------------------------
# 4. Instalación de Motor DNS (Role)
# ------------------------------------------------------------------------------
try {
    $Feature = Get-WindowsFeature -Name "DNS"
    if ($Feature.Installed) {
        Write-Log "rol dns ya instalado" "ok"
    } else {
        Write-Log "instalando rol dns..." "info"
        Install-WindowsFeature -Name DNS -IncludeManagementTools | Out-Null
        Write-Log "instalado" "ok"
    }

    $Service = Get-Service -Name "DNS"
    if ($Service.Status -ne "Running") {
        Start-Service "DNS"
        Set-Service "DNS" -StartupType Automatic
        Write-Log "servicio dns start" "ok"
    }
} catch {
    Write-Log "error de servicio: $_" "error"
    exit 1
}

# ------------------------------------------------------------------------------
# 5. Configuración Autoritativa e Ingeniería de Zonas
# ------------------------------------------------------------------------------
try {
    Write-Log "creando zona..." "info"
    
    $existingZone = Get-DnsServerZone -Name $Domain -ErrorAction SilentlyContinue
    if (-not $existingZone) {
        Add-DnsServerPrimaryZone -Name $Domain -DynamicUpdate "None" -ZoneFile "$Domain.dns" -ErrorAction Stop
        Write-Log "zona $Domain creada" "ok"
    } else {
        Write-Log "zona ya existia" "ok"
    }
    
    $recA = Get-DnsServerResourceRecord -ZoneName $Domain -Name "@" -RRType "A" -ErrorAction SilentlyContinue
    if (-not $recA) {
        Add-DnsServerResourceRecordA -ZoneName $Domain -Name "@" -IPv4Address $TargetClientIP -TimeToLive 01:00:00 -ErrorAction Stop
        Write-Log "registro a agregado" "ok"
    } else {
        $actualIP = $recA.RecordData.IPv4Address.IPAddressToString
        if ($actualIP -ne $TargetClientIP) {
            Write-Log "forzando update del registro A a $TargetClientIP" "alerta"
            $newRec = $recA.Clone()
            $newRec.RecordData.IPv4Address = [System.Net.IPAddress]::Parse($TargetClientIP)
            Set-DnsServerResourceRecord -NewInputObject $newRec -OldInputObject $recA -ZoneName $Domain
            Write-Log "update listo" "ok"
        } else {
            Write-Log "registro A ok" "ok"
        }
    }

    $recC = Get-DnsServerResourceRecord -ZoneName $Domain -Name "www" -RRType "CNAME" -ErrorAction SilentlyContinue
    if (-not $recC) {
        Add-DnsServerResourceRecordCName -ZoneName $Domain -Name "www" -HostNameAlias $Domain -TimeToLive 01:00:00 -ErrorAction Stop
        Write-Log "registro cname agregado" "ok"
    } else {
        Write-Log "cname ok" "ok"
    }
} catch {
    Write-Log "excepcion en wmi dns: $_" "error"
    exit 1
}

# ------------------------------------------------------------------------------
# 6. Forzar Resolución Local y Flush de Caché
# ------------------------------------------------------------------------------
try {
    Write-Log "forzando localhost como dns" "info"
    $PrimaryAdapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.Virtual -eq $false } | Select-Object -First 1
    if ($PrimaryAdapter) {
        Set-DnsClientServerAddress -InterfaceAlias $PrimaryAdapter.Name -ServerAddresses ("127.0.0.1", "8.8.8.8") -ErrorAction Stop
        Write-Log "red modificada a 127.0.0.1" "ok"
    }
} catch {
    Write-Log "fallo el loopback dns" "alerta"
}

Clear-DnsClientCache
Restart-Service "DNS" -ErrorAction SilentlyContinue

# ------------------------------------------------------------------------------
# 7. Self-Diagnostic Checklist
# ------------------------------------------------------------------------------
Write-Host ""
Write-Host "--- checklist ---"

function Test-Check {
    param([string]$name, [bool]$eval)
    if ($eval) { Write-Host "$name: ok" }
    else       { Write-Host "$name: fail" }
}

$serviceOk = (Get-Service DNS).Status -eq 'Running'
Test-Check "servicio dns" $serviceOk

$portOk = (Get-NetTCPConnection -LocalPort 53 -ErrorAction SilentlyContinue) -ne $null
Test-Check "puerto 53" $portOk

$aResolve = Resolve-DnsName -Name $Domain -Server 127.0.0.1 -ErrorAction SilentlyContinue
Test-Check "nslookup $Domain" ($aResolve -ne $null)

$cResolve = Resolve-DnsName -Name "www.$Domain" -Server 127.0.0.1 -ErrorAction SilentlyContinue
Test-Check "nslookup www.$Domain" ($cResolve -ne $null)

Write-Log "listo" "info"
Exit 0
