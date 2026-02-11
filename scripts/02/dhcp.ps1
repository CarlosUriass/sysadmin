[CmdletBinding(DefaultParameterSetName = 'Full')]
param(
    [Parameter(ParameterSetName = 'Install')]
    [Alias('i')]
    [switch]$Install,

    [Parameter(ParameterSetName = 'Configure')]
    [Alias('c')]
    [switch]$Configure,

    [Parameter(ParameterSetName = 'Leases')]
    [Alias('l')]
    [switch]$Leases,

    [Parameter(ParameterSetName = 'Status')]
    [Alias('s')]
    [switch]$Status,

    [Parameter(ParameterSetName = 'Help')]
    [Alias('h')]
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$IFACE      = 'Ethernet 2'          # interfaz 2 = red interna VMs (no tocar Ethernet 1 = bridged/internet)
$SCOPE_MASK = '255.255.255.0'
$PREFIX_LEN = 24

$BLACKLIST = @(
    '127.','255.255.255','0.0.0.0'
    '224.','225.','226.','227.','228.','229.'
    '230.','231.','232.','233.','234.','235.','236.','237.','238.','239.'
)

# --- funciones auxiliares ---

function Verificar-Administrador {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "error: ejecutar como administrador"
        exit 1
    }
}

function Validar-IP {
    param([string]$IP)
    if ($IP -notmatch '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$') {
        Write-Host "error: formato invalido '$IP'"
        return $false
    }
    foreach ($o in $Matches[1..4]) {
        if ([int]$o -gt 255) {
            Write-Host "error: octeto fuera de rango en '$IP'"
            return $false
        }
    }
    return $true
}

function IP-EnBlacklist {
    param([string]$IP)
    foreach ($e in $BLACKLIST) {
        if ($IP -eq $e -or $IP.StartsWith($e)) {
            Write-Host "error: IP '$IP' en blacklist ('$e')"
            return $true
        }
    }
    return $false
}

function Solicitar-IP {
    param([string]$Prompt, [string]$Default)
    while ($true) {
        $r = Read-Host "$Prompt [$Default]"
        if ([string]::IsNullOrWhiteSpace($r)) { $r = $Default }
        if (-not (Validar-IP -IP $r)) { Write-Host "intente de nuevo."; continue }
        if (IP-EnBlacklist -IP $r) { Write-Host "intente otra IP."; continue }
        return $r
    }
}

function Obtener-Subred {
    param([string]$IP)
    $p = $IP.Split('.'); return "$($p[0]).$($p[1]).$($p[2]).0"
}

function Obtener-Prefijo {
    param([string]$IP)
    $p = $IP.Split('.'); return "$($p[0]).$($p[1]).$($p[2])"
}

function Obtener-IPActual {
    $a = Get-NetIPAddress -InterfaceAlias $IFACE -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($a) { return $a.IPAddress }
    return $null
}

# --- cambio de ip estatica si cambia subred ---

function Adaptar-IPEstatica {
    param([string]$RangoIP)

    $nuevaSub = Obtener-Prefijo -IP $RangoIP
    $ipAct    = Obtener-IPActual
    if ([string]::IsNullOrEmpty($ipAct)) { $ipAct = '0.0.0.0' }
    $subAct = Obtener-Prefijo -IP $ipAct

    if ($subAct -eq $nuevaSub) {
        Write-Host "ip actual ($ipAct) ya en subred $nuevaSub.0/$PREFIX_LEN"
        return
    }

    $nuevaIP = "$nuevaSub.10"
    Write-Host "subred diferente: actual=$ipAct nueva=$nuevaSub.0/$PREFIX_LEN"
    Write-Host "cambiando ip de $IFACE a $nuevaIP/$PREFIX_LEN..."

    Get-NetIPAddress -InterfaceAlias $IFACE -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue

    Get-NetRoute -InterfaceAlias $IFACE -ErrorAction SilentlyContinue |
        Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' } |
        Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

    New-NetIPAddress -InterfaceAlias $IFACE -IPAddress $nuevaIP -PrefixLength $PREFIX_LEN -ErrorAction Stop | Out-Null
    Write-Host "ip cambiada a $nuevaIP"
}

# --- instalacion idempotente ---

function Instalar-DHCP {
    Write-Host "=== instalacion ==="

    $f = Get-WindowsFeature -Name DHCP -ErrorAction SilentlyContinue
    if ($f -and $f.Installed) {
        Write-Host "dhcp server ya instalado"
    } else {
        Write-Host "instalando dhcp server..."
        Install-WindowsFeature -Name DHCP -IncludeManagementTools -ErrorAction Stop | Out-Null
        Write-Host "instalacion completada"
    }

    $svc = Get-Service -Name DHCPServer -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.StartType -ne 'Automatic') { Set-Service -Name DHCPServer -StartupType Automatic }
        if ($svc.Status -ne 'Running') { Start-Service -Name DHCPServer }
        Write-Host "servicio dhcpserver activo, inicio automatico"
    }

    try {
        $ip = Obtener-IPActual
        if ($ip) { Add-DhcpServerInDC -DnsName $env:COMPUTERNAME -IPAddress $ip -ErrorAction SilentlyContinue }
    } catch {
        Write-Host "aviso: no se autorizo en AD (puede no ser necesario)"
    }

    Write-Host "interfaz: $IFACE"
}

# --- configuracion interactiva ---

function Configurar-DHCP {
    Write-Host "=== configuracion del scope ==="

    $scopeName = ''
    while ([string]::IsNullOrWhiteSpace($scopeName)) {
        $scopeName = Read-Host "nombre del scope"
        if ([string]::IsNullOrWhiteSpace($scopeName)) { Write-Host "nombre vacio." }
    }

    Write-Host "parametros de red (enter = default):"

    $startIP = Solicitar-IP -Prompt "ip inicial" -Default "192.168.100.50"
    $endIP   = Solicitar-IP -Prompt "ip final"   -Default "192.168.100.150"

    # defaults dinamicos basados en la subred del rango
    $prefijo = Obtener-Prefijo -IP $startIP
    $gwDefault  = "$prefijo.1"
    $dnsDefault = "$prefijo.1"

    $gateway = Solicitar-IP -Prompt "gateway"     -Default $gwDefault
    $dns     = Solicitar-IP -Prompt "dns"         -Default $dnsDefault

    $lease = Read-Host "lease en segundos [600]"
    if ([string]::IsNullOrWhiteSpace($lease)) { $lease = '600' }
    while ($lease -notmatch '^\d+$' -or [int]$lease -lt 60) {
        Write-Host "valor numerico >= 60"
        $lease = Read-Host "lease en segundos [600]"
        if ([string]::IsNullOrWhiteSpace($lease)) { $lease = '600' }
    }
    $leaseSeconds = [int]$lease

    $sp = Obtener-Prefijo -IP $startIP
    $ep = Obtener-Prefijo -IP $endIP
    if ($sp -ne $ep) { Write-Host "error: ips en diferente subred"; exit 1 }

    $sl = [int]($startIP.Split('.')[-1])
    $el = [int]($endIP.Split('.')[-1])
    if ($sl -ge $el) { Write-Host "error: ip inicial >= ip final"; exit 1 }

    $subnet = Obtener-Subred -IP $startIP

    Write-Host "=== verificacion de subred ==="
    Adaptar-IPEstatica -RangoIP $startIP

    # idempotencia: eliminar scope previo con mismo nombre
    $existing = Get-DhcpServerv4Scope -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $scopeName }
    if ($existing) {
        Write-Host "eliminando scope previo '$scopeName'..."
        Remove-DhcpServerv4Scope -ScopeId $existing.ScopeId -Force -ErrorAction SilentlyContinue
    }

    Write-Host "=== creando scope ==="

    $dur = [TimeSpan]::FromSeconds($leaseSeconds)

    Add-DhcpServerv4Scope -Name $scopeName `
                          -StartRange $startIP `
                          -EndRange   $endIP `
                          -SubnetMask $SCOPE_MASK `
                          -LeaseDuration $dur `
                          -State Active `
                          -ErrorAction Stop

    Set-DhcpServerv4OptionValue -ScopeId $subnet `
                                -Router $gateway `
                                -DnsServer $dns `
                                -ErrorAction Stop

    Write-Host "scope: $scopeName | subred: $subnet/$PREFIX_LEN"
    Write-Host "rango: $startIP - $endIP | gw: $gateway | dns: $dns | lease: ${leaseSeconds}s"

    Restart-Service -Name DHCPServer -Force
    Set-Service -Name DHCPServer -StartupType Automatic
    Write-Host "servicio reiniciado"
}

# --- leases ---

function Mostrar-Leases {
    Write-Host "=== leases activas ==="
    $scopes = Get-DhcpServerv4Scope -ErrorAction SilentlyContinue
    if (-not $scopes) { Write-Host "sin scopes"; return }

    $total = 0
    foreach ($s in $scopes) {
        $ll = Get-DhcpServerv4Lease -ScopeId $s.ScopeId -ErrorAction SilentlyContinue
        if ($ll) {
            $total += @($ll).Count
            foreach ($l in $ll) {
                $h = if ($l.HostName) { $l.HostName } else { '-' }
                Write-Host ("  {0,-18} {1,-22} {2}" -f $l.IPAddress, $l.ClientId, $h)
            }
        }
    }
    if ($total -eq 0) { Write-Host "sin leases" }
    else { Write-Host "$total lease(s)" }
}

# --- estado ---

function Mostrar-Estado {
    Write-Host "=== estado del servicio ==="
    $svc = Get-Service -Name DHCPServer -ErrorAction SilentlyContinue
    if (-not $svc) { Write-Host "servicio no encontrado"; return }

    if ($svc.Status -eq 'Running') { Write-Host "servicio: activo" }
    else { Write-Host "servicio: inactivo ($($svc.Status))" }

    Write-Host "  nombre: $($svc.DisplayName) | estado: $($svc.Status) | inicio: $($svc.StartType)"

    $scopes = Get-DhcpServerv4Scope -ErrorAction SilentlyContinue
    if ($scopes) {
        Write-Host "  scopes:"
        foreach ($s in $scopes) {
            Write-Host "    - $($s.Name): $($s.StartRange)-$($s.EndRange) ($($s.State))"
        }
    }
}

# --- ayuda ---

function Mostrar-Ayuda {
    Write-Host "uso: .\dhcp.ps1 [opcion]"
    Write-Host "  -i  instalar    -c  configurar    -l  leases    -s  estado    -h  ayuda"
    Write-Host "  sin opciones = flujo completo"
}

# --- main ---

Write-Host "=== dhcp server - windows ==="

if ($Help)   { Mostrar-Ayuda; exit 0 }
if ($Status) { Mostrar-Estado; exit 0 }

Verificar-Administrador

if ($Install)        { Instalar-DHCP }
elseif ($Configure)  { Instalar-DHCP; Configurar-DHCP }
elseif ($Leases)     { Mostrar-Leases }
else                 { Instalar-DHCP; Configurar-DHCP; Mostrar-Estado; Mostrar-Leases }
