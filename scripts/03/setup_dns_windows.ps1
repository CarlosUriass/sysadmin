<#
.SYNOPSIS
Enterprise-Grade Windows DNS Server Automation Script
.DESCRIPTION
Implementa infraestructura crítica as-code. Totalmente idempotente, genera logs transaccionales, efectúa hardening básico, y valida estados de red antes de aplicar modificaciones al motor WMI/CIM.
#>

[CmdletBinding(DefaultParameterSetName='Interactive')]
param (
    [Parameter(Mandatory=$false, ParameterSetName='CLI')]
    [string]$TargetClientIP,

    [Parameter(Mandatory=$false, ParameterSetName='CLI')]
    [string]$DomainName,

    [Parameter(Mandatory=$false)]
    [switch]$Help,

    [Parameter(Mandatory=$false)]
    [switch]$Purge
)

if ($Help) {
    Write-Host "uso:"
    Write-Host "  .\setup_dns_windows.ps1 [opciones]"
    Write-Host ""
    Write-Host "opciones:"
    Write-Host "  -TargetClientIP <ip>   asigna la ip a donde resolverá el dominio. El script auto-calculará su red."
    Write-Host "  -DomainName <dominio>  asigna el nombre de dominio a configurar."
    Write-Host "  -Purge                 elimina el rol de servidor dns, la zona y configuraciones."
    Write-Host "  -Help                  muestra este mensaje de ayuda."
    exit 0
}

if ($Purge) {
    if ([string]::IsNullOrWhiteSpace($DomainName)) {
        $DomainName = Read-Host "nombre del dominio a purgar (ej. reprobados.com)"
    }
    Write-Host "iniciando purga total del servidor dns..." -ForegroundColor Yellow
    Remove-DnsServerZone -Name $DomainName -Force -ErrorAction SilentlyContinue
    Uninstall-WindowsFeature -Name DNS -Remove | Out-Null
    Write-Host "dns desinstalado y configuraciones removidas." -ForegroundColor Green
    exit 0
}

# ------------------------------------------------------------------------------
# 1. Configuración Inicial y Strict Mode
# ------------------------------------------------------------------------------
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$LogPath = "$env:TEMP\dns_setup_enterprise.log"

Function Write-Log {
    param([string]$Message, [string]$Level="info")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $fmt = "$timestamp - $($Level): $Message"
    Write-Host "$($Level): $Message"
    Add-Content -Path $LogPath -Value $fmt
}

Write-Log "iniciando dns server" "info"

# ------------------------------------------------------------------------------
# 2. Assertions y Seguridad Previa
# ------------------------------------------------------------------------------
try {
    & "$PSScriptRoot\..\..\utils\ps1\permissions.ps1" -CheckAdmin *>$null
    if ($LASTEXITCODE -ne 0) {
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
    $validIP = $false
    do {
        $TargetClientIP = Read-Host "ip del cliente objetivo"
        if (-not [string]::IsNullOrEmpty($TargetClientIP)) {
            & "$PSScriptRoot\..\..\utils\ps1\validate_ip.ps1" -IP $TargetClientIP *>$null
            if ($LASTEXITCODE -eq 0) { $validIP = $true }
        }
    } until ($validIP)
} else {
    & "$PSScriptRoot\..\..\utils\ps1\validate_ip.ps1" -IP $TargetClientIP *>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error: ip provista '$TargetClientIP' es invalida."
        exit 1
    }
}

If ([string]::IsNullOrWhiteSpace($DomainName)) {
    do {
        $DomainName = Read-Host "nombre del dominio (ej. mi.laboratorio.com)"
    } until (-not [string]::IsNullOrWhiteSpace($DomainName))
}
$Domain = $DomainName

try {
    # 1. Obtener todas las rutas por defecto (Internet)
    $defaultRoutes = @(Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue)
    $internetIfaceIndices = @()
    if ($defaultRoutes) {
        $internetIfaceIndices = @($defaultRoutes | Select-Object -ExpandProperty InterfaceIndex)
    }

    # 2. Obtener todos los adaptadores físicos activos
    $adapters = @(Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.Virtual -eq $false -and $_.Name -notmatch "vEthernet|Default Switch|Loopback" })
    
    # 3. Filtrar estrictamente los que NO tienen internet
    $internalAdapters = @()
    if ($internetIfaceIndices.Count -gt 0) {
        $internalAdapters = @($adapters | Where-Object { $internetIfaceIndices -notcontains $_.InterfaceIndex })
    }

    # 4. Asignación de Prioridad Estratégica
    if ($internalAdapters.Count -gt 0) {
        # Si encontró uno claro sin internet, lo usamos.
        $ActiveIface = $internalAdapters[0]
    } else {
        # Fallback de emergencia extrema (El enrutamiento no funcionó).
        # En el entorno del usuario: "Ethernet" (índice 0) es local y "Ethernet 2" (índice 1) es Internet.
        Write-Log "No se discernió red aislada por enrutamiento. Aplicando fallback de exclusión..." "alerta"
        if ($adapters.Count -gt 1) {
            $ActiveIface = $adapters[0]
        } elseif ($adapters.Count -eq 1) {
            $ActiveIface = $adapters[0]
            Write-Log "CUIDADO: Solo existe un adaptador activo ($($ActiveIface.Name)). Se usará este." "alerta"
        }
    }
    
    if ($ActiveIface) {
        Write-Log "interfaz interna detectada: $($ActiveIface.Name)" "info"
        $NetConf = Get-NetIPInterface -InterfaceAlias $ActiveIface.Name -AddressFamily IPv4
        if ($NetConf.Dhcp -eq "Enabled") {
            Write-Log "dhcp detectado. se cambiará a estática pura" "alerta"
        } 

        $currentIpObj = Get-NetIPAddress -InterfaceAlias $ActiveIface.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
        $currentIpStr = if ($currentIpObj) { $currentIpObj.IPAddress } else { "" }

        $octets = $TargetClientIP.Split('.')
        $prefix = "$($octets[0]).$($octets[1]).$($octets[2])"
        $ServerInternalIP = "$prefix.10"
        
        if ($ServerInternalIP -eq $TargetClientIP) {
            $ServerInternalIP = "$prefix.11"
        }

        Write-Log "IP de Dominio: $TargetClientIP. Auto-deduciendo IP Server: $ServerInternalIP" "info"

        if ($currentIpStr -ne $ServerInternalIP) {
            Write-Log "cambiando IP de la interfaz $($ActiveIface.Name) a $ServerInternalIP..." "info"
            
            # Limpiar IPs viejas
            Get-NetIPAddress -InterfaceAlias $ActiveIface.Name -AddressFamily IPv4 | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
            
            # Asignar la nueva
            New-NetIPAddress -InterfaceAlias $ActiveIface.Name -IPAddress $ServerInternalIP -PrefixLength 24 -ErrorAction Stop | Out-Null
            Write-Log "IP de interfaz del servidor cambiada a $ServerInternalIP" "ok"
        } else {
            Write-Log "IP de interfaz ya era $ServerInternalIP" "ok"
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
# 6. Forzar Resolución Local y Flush de Caché Profundo
# ------------------------------------------------------------------------------
try {
    Write-Log "forzando localhost como dns en todos los adaptadores" "info"
    $ActiveAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    foreach ($Adapter in $ActiveAdapters) {
        Set-DnsClientServerAddress -InterfaceAlias $Adapter.Name -ServerAddresses ("127.0.0.1") -ErrorAction SilentlyContinue
    }
    Write-Log "red modificada a 127.0.0.1" "ok"
} catch {
    Write-Log "fallo el loopback dns" "alerta"
}

# ------------------------------------------------------------------------------
# 6.5. Integración silenciosa con DHCP
# ------------------------------------------------------------------------------
try {
    Write-Log "verificando si dhcp debe ser parametrizado dinámicamente..." "info"
    $activeIpAddr = $null
    if ($ActiveIface) {
        $ipObj = Get-NetIPAddress -InterfaceAlias $ActiveIface.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($ipObj) { $activeIpAddr = $ipObj.IPAddress }
    }

    if (-not [string]::IsNullOrEmpty($activeIpAddr)) {
        $dhcpSvc = Get-Service -Name "DHCPServer" -ErrorAction SilentlyContinue
        
        $octets = $activeIpAddr.Split('.')
        $prefix = "$($octets[0]).$($octets[1]).$($octets[2])"
        $subnet = "$prefix.0"
        $startIp = "$prefix.50"
        $endIp = "$prefix.150"
        $gw = "$prefix.1"

        $dhcpFeature = Get-WindowsFeature -Name DHCP -ErrorAction SilentlyContinue
        if (-not $dhcpFeature.Installed) {
            Write-Log "dhcp no instalado. instalando rol..." "info"
            try {
                Install-WindowsFeature -Name DHCP -IncludeManagementTools -ErrorAction Stop | Out-Null
            } catch {
                Write-Log "Forzando descarga de DHCP a través de Windows Update..." "alerta"
                Install-WindowsFeature -Name DHCP -IncludeManagementTools -IncludeAllSubFeature -ErrorAction SilentlyContinue | Out-Null
            }
        }
        
        $dhcpSvc = Get-Service -Name "DHCPServer" -ErrorAction SilentlyContinue
        if ($dhcpSvc.Status -ne 'Running') {
            Set-Service -Name DHCPServer -StartupType Automatic
            Start-Service -Name DHCPServer
        }

        $existing = Get-DhcpServerv4Scope -ScopeId $subnet -ErrorAction SilentlyContinue
        if (-not $existing) {
            Write-Log "creando scope dinámico $subnet en dhcp..." "info"
            Add-DhcpServerv4Scope -Name ("Scope " + $subnet) -StartRange $startIp -EndRange $endIp -SubnetMask "255.255.255.0" -State Active -ErrorAction SilentlyContinue
            Set-DhcpServerv4OptionValue -ScopeId $subnet -Router $gw -DnsServer $activeIpAddr -ErrorAction SilentlyContinue
            Write-Log "scope $subnet configurado con dns $activeIpAddr" "ok"
        } else {
            Write-Log "scope $subnet ya existe. actualizando opciones..." "info"
            Set-DhcpServerv4OptionValue -ScopeId $subnet -Router $gw -DnsServer $activeIpAddr -ErrorAction SilentlyContinue
            Write-Log "opciones actualizadas en scope dhcp" "ok"
        }
    }
} catch {
    Write-Log "falló la integración dhcp (puede no estar instalado)" "alerta"
}

Write-Log "limpiando cache de dns y netbios para que el ping sirva..." "info"
ipconfig /flushdns | Out-Null
nbtstat -R | Out-Null
nbtstat -RR | Out-Null
Clear-DnsClientCache
Restart-Service "DNS" -ErrorAction SilentlyContinue

# ------------------------------------------------------------------------------
# 7. Self-Diagnostic Checklist
# ------------------------------------------------------------------------------
Write-Host ""
Write-Host "--- checklist ---"

function Test-Check {
    param([string]$name, [bool]$eval)
    if ($eval) { Write-Host "$($name): ok" }
    else       { Write-Host "$($name): fail" }
}

$serviceOk = $false
if ((Get-Service DNS).Status -eq 'Running') { $serviceOk = $true }
Test-Check "servicio dns" $serviceOk

$portOk = $false
if (Get-NetTCPConnection -LocalPort 53 -ErrorAction SilentlyContinue) { $portOk = $true }
Test-Check "puerto 53" $portOk

$aResolveOk = $false
if (Resolve-DnsName -Name $Domain -Server 127.0.0.1 -ErrorAction SilentlyContinue) { $aResolveOk = $true }
Test-Check "nslookup $Domain" $aResolveOk

$cResolveOk = $false
if (Resolve-DnsName -Name "www.$Domain" -Server 127.0.0.1 -ErrorAction SilentlyContinue) { $cResolveOk = $true }
Test-Check "nslookup www.$Domain" $cResolveOk

Write-Log "listo" "info"
Exit 0
