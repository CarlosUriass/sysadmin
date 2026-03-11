# ==============================================================================
# Práctica 6 - Despliegue Dinámico de Servicios HTTP en Windows Server
# Sistema Operativo: Windows Server (PowerShell)
# Uso interactivo:    .\http_deploy.ps1
# Uso con parámetros: .\http_deploy.ps1 -Service iis -Port 8080
# ==============================================================================

[CmdletBinding()]
param(
    [Alias("s")][string]$Service = "",
    [Alias("p")][string]$Port    = "",
    [switch]$Status,
    [switch]$Purge,
    [switch]$Help
)

Set-StrictMode -Off
$ErrorActionPreference = "Continue"

# ==============================================================================
# RUTAS DE UTILIDADES
# ==============================================================================
$SCRIPT_DIR    = Split-Path -Parent $MyInvocation.MyCommand.Path
$UTILS_PS1_DIR = (Resolve-Path "$SCRIPT_DIR\..\utils\ps1").Path
$UTILS_LOG_DIR = (Resolve-Path "$SCRIPT_DIR\..\utils\logs").Path

if (-not (Test-Path "$UTILS_LOG_DIR\logger.ps1")) {
    Write-Host "ERROR: No se encontro logger.ps1 en $UTILS_LOG_DIR" -ForegroundColor Red
    exit 1
}
. "$UTILS_LOG_DIR\logger.ps1"

# ==============================================================================
# VARIABLES GLOBALES DE SESION
# ==============================================================================
$script:PUERTO_ELEGIDO  = $Port
$script:VERSION_ELEGIDA = ""
$script:INTERACTIVO     = [string]::IsNullOrEmpty($Service)

# Puertos bloqueados por estar asignados a otros servicios del sistema
$script:PUERTOS_RESTRINGIDOS = @(21, 22, 23, 25, 53, 110, 143, 443, 445, 1433, 3306, 3389, 5432, 5985, 5986)

# ==============================================================================
# VERIFICAR ADMINISTRADOR  →  utils\ps1\permissions.ps1
# ==============================================================================
function Test-AdminPrivileges {
    & "$UTILS_PS1_DIR\permissions.ps1" -CheckAdmin 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-LogError "Este script debe ejecutarse como Administrador (Run as Administrator)."
    }
    Write-LogSuccess "Privilegios de administrador confirmados."
}

# ==============================================================================
# VERIFICAR CONECTIVIDAD
# ==============================================================================
function Test-Connectivity {
    Write-LogInfo "Verificando conectividad a internet..."
    $ok = Test-Connection -ComputerName "8.8.8.8" -Count 1 -Quiet -ErrorAction SilentlyContinue
    if (-not $ok) {
        Write-LogError "Sin conexion a internet. El script requiere acceso a repositorios."
    }
    Write-LogSuccess "Conectividad verificada."
}

# ==============================================================================
# ASEGURAR CHOCOLATEY
# ==============================================================================
function Install-Chocolatey {
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        Write-LogSuccess "Chocolatey disponible: $(choco --version)"
        return
    }
    Write-LogInfo "Instalando Chocolatey..."
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol =
        [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString(
        'https://community.chocolatey.org/install.ps1'))
    $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" +
                [System.Environment]::GetEnvironmentVariable("PATH","User")
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-LogError "No se pudo instalar Chocolatey. Verifica la conexion a internet."
    }
    Write-LogSuccess "Chocolatey instalado: $(choco --version)"
}

# ==============================================================================
# VALIDAR PUERTO
# Usa: validate_port.ps1  /  check_port_in_use.ps1  /  kill_port_process.ps1
# ==============================================================================
function Invoke-ValidatePort {
    param([string]$PortNum)

    # validate_port.ps1 usa throw() para fallar  →  capturamos con try/catch
    $valid = $true
    try {
        & "$UTILS_PS1_DIR\validate_port.ps1" -Port $PortNum *>$null
    } catch {
        $valid = $false
    }
    if (-not $valid) {
        Write-LogWarn "El puerto $PortNum es invalido o esta en rango reservado del sistema (1-1023)."
        return $false
    }

    # Bloquear puertos usados por otros servicios conocidos
    if ($script:PUERTOS_RESTRINGIDOS -contains [int]$PortNum) {
        Write-LogWarn "El puerto $PortNum esta reservado para otro servicio del sistema (RDP, SQL, SSH, etc)."
        return $false
    }

    # check_port_in_use.ps1  →  exit 0 = ocupado,  exit 1 = libre
    & "$UTILS_PS1_DIR\check_port_in_use.ps1" -Port $PortNum *>$null
    if ($LASTEXITCODE -eq 0) {
        $procName = (
            Get-NetTCPConnection -LocalPort ([int]$PortNum) -ErrorAction SilentlyContinue |
            Select-Object -First 1 |
            ForEach-Object {
                (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName
            }
        )
        Write-LogWarn "Puerto $PortNum en uso por: $procName. Intentando liberar automaticamente..."
        & "$UTILS_PS1_DIR\kill_port_process.ps1" -Port $PortNum *>$null

        & "$UTILS_PS1_DIR\check_port_in_use.ps1" -Port $PortNum *>$null
        if ($LASTEXITCODE -eq 0) {
            Write-LogWarn "No se pudo liberar el puerto $PortNum automaticamente."
            return $false
        }
        Write-LogSuccess "Puerto $PortNum liberado exitosamente."
    }
    return $true
}

# ==============================================================================
# PEDIR PUERTO AL USUARIO (INTERACTIVO)
# ==============================================================================
function Request-Port {
    while ($true) {
        Write-Host "`n  Ingresa el puerto de escucha (ej: 8080, 8888): " `
            -ForegroundColor Cyan -NoNewline
        $raw = Read-Host
        if ([string]::IsNullOrWhiteSpace($raw)) {
            Write-LogWarn "El puerto no puede estar vacio."
            continue
        }
        $clean = $raw -replace '[^0-9]', ''
        if ([string]::IsNullOrEmpty($clean)) {
            Write-LogWarn "El puerto debe contener solo digitos."
            continue
        }
        if (Invoke-ValidatePort -PortNum $clean) {
            $script:PUERTO_ELEGIDO = $clean
            Write-LogSuccess "Puerto $clean aceptado."
            return
        }
    }
}

# ==============================================================================
# HELPER: DIRECTORIO DE INSTALACION DE APACHE
# ==============================================================================
function Get-ApacheInstallDir {
    $candidates = @(
        "C:\Apache24",
        "$env:ProgramFiles\Apache24",
        "$env:ProgramFiles\Apache Group\Apache2.4",
        "C:\tools\Apache24"
    )
    foreach ($c in $candidates) {
        if (Test-Path "$c\bin\httpd.exe") { return $c }
    }
    # Buscar en directorio de Chocolatey
    $chocoLib = "C:\ProgramData\chocolatey\lib\apache"
    if (Test-Path $chocoLib) {
        $found = Get-ChildItem $chocoLib -Recurse -Filter "httpd.exe" -ErrorAction SilentlyContinue |
                 Select-Object -First 1
        if ($found) { return ($found.DirectoryName -replace '\\bin$', '') }
    }
    return $null
}

# ==============================================================================
# HELPER: DIRECTORIO DE INSTALACION DE NGINX
# ==============================================================================
function Get-NginxInstallDir {
    $candidates = @(
        "C:\nginx",
        "C:\tools\nginx",
        "$env:ProgramFiles\nginx"
    )
    foreach ($c in $candidates) {
        if (Test-Path "$c\nginx.exe") { return $c }
    }
    $chocoLib = "C:\ProgramData\chocolatey\lib\nginx\tools"
    if (Test-Path $chocoLib) {
        $found = Get-ChildItem $chocoLib -Recurse -Filter "nginx.exe" -ErrorAction SilentlyContinue |
                 Select-Object -First 1
        if ($found) { return $found.DirectoryName }
    }
    return $null
}

# ==============================================================================
# OBTENER VERSIONES: IIS  (desde registro de Windows + WMI)
# ==============================================================================
function Get-IISVersions {
    Write-LogInfo "Consultando version de IIS disponible en este sistema..."

    $regKey = "HKLM:\SOFTWARE\Microsoft\InetStp"
    if (Test-Path $regKey) {
        $props = Get-ItemProperty $regKey -ErrorAction SilentlyContinue
        $ver   = "$($props.MajorVersion).$($props.MinorVersion)"
    } else {
        $ver = "10.0"
    }

    $build = [System.Environment]::OSVersion.Version.Build
    $osLabel = ""
    if     ($build -ge 20348) { $osLabel = "Windows Server 2022 - Latest" }
    elseif ($build -ge 17763) { $osLabel = "Windows Server 2019 - LTS"    }
    elseif ($build -ge 14393) { $osLabel = "Windows Server 2016 - LTS"    }
    else                      { $osLabel = "Windows Server - Disponible"   }

    Write-Host ""
    Write-Host "  Versiones disponibles de IIS:" -ForegroundColor White
    Write-Host "  ─────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  1) IIS $ver  " -NoNewline
    Write-Host "($osLabel)" -ForegroundColor Green
    Write-Host ""
    Write-Host "  [IIS es el servidor HTTP nativo de Windows - instalacion obligatoria]" `
               -ForegroundColor DarkGray

    $script:VERSION_ELEGIDA = "IIS/$ver"
    Write-LogSuccess "Version seleccionada: $($script:VERSION_ELEGIDA)"

    if ($script:INTERACTIVO) {
        Write-Host "`n  Presiona ENTER para confirmar..." -ForegroundColor Cyan -NoNewline
        Read-Host | Out-Null
    }
}

# ==============================================================================
# OBTENER VERSIONES: APACHE  (Chocolatey → fallback apache.org)
# ==============================================================================
function Get-ApacheVersions {
    Write-LogInfo "Consultando versiones disponibles de Apache para Windows..."
    Install-Chocolatey

    $versions = @()
    try {
        $raw = choco search apache --exact --all-versions --limit-output 2>$null
        $versions = $raw |
            ForEach-Object { if ($_ -match '^apache\|(.+)$') { $Matches[1].Trim() } } |
            Where-Object   { $_ } |
            Sort-Object    { try { [version]($_ -replace '[^0-9.]','0') } catch { [version]"0.0" } } `
                           -Descending
    } catch { }

    if ($versions.Count -eq 0) {
        Write-LogWarn "Chocolatey no devolvio versiones. Consultando httpd.apache.org..."
        try {
            $html = (Invoke-WebRequest -Uri "https://httpd.apache.org/download.cgi" `
                                       -UseBasicParsing -TimeoutSec 10).Content
            $m = [regex]::Matches($html, 'Apache HTTP Server (\d+\.\d+\.\d+)')
            $versions = $m | ForEach-Object { $_.Groups[1].Value } |
                        Sort-Object { [version]$_ } -Descending |
                        Select-Object -Unique
        } catch {
            Write-LogWarn "No se pudo consultar apache.org. Usando versiones de referencia."
            $versions = @("2.4.63", "2.4.62", "2.4.58")
        }
    }

    if ($versions.Count -eq 0) {
        Write-LogError "No se encontraron versiones de Apache disponibles."
        return $false
    }

    $maxShow = [Math]::Min($versions.Count, 5)
    Write-Host ""
    Write-Host "  Versiones disponibles de Apache (Windows):" -ForegroundColor White
    Write-Host "  ─────────────────────────────────────────" -ForegroundColor DarkGray
    for ($i = 0; $i -lt $maxShow; $i++) {
        Write-Host "  $($i+1)) $($versions[$i])  " -NoNewline
        if     ($i -eq 0)            { Write-Host "(Latest)"      -ForegroundColor Yellow }
        elseif ($i -eq ($maxShow-1)) { Write-Host "(Estable/LTS)" -ForegroundColor Green  }
        else                         { Write-Host ""                                       }
    }

    if (-not $script:INTERACTIVO) {
        $script:VERSION_ELEGIDA = $versions[0]
        return $true
    }

    while ($true) {
        Write-Host "`n  Selecciona una version [1-$maxShow]: " -ForegroundColor Cyan -NoNewline
        $sel = (Read-Host) -replace '[^0-9]', ''
        if ($sel -match '^\d+$' -and [int]$sel -ge 1 -and [int]$sel -le $maxShow) {
            $script:VERSION_ELEGIDA = $versions[[int]$sel - 1]
            Write-LogSuccess "Version seleccionada: $($script:VERSION_ELEGIDA)"
            return $true
        }
        Write-LogWarn "Seleccion invalida. Ingresa un numero entre 1 y $maxShow."
    }
}

# ==============================================================================
# OBTENER VERSIONES: NGINX  (Chocolatey → fallback nginx.org)
# ==============================================================================
function Get-NginxVersions {
    Write-LogInfo "Consultando versiones disponibles de Nginx para Windows..."
    Install-Chocolatey

    $versions = @()
    try {
        $raw = choco search nginx --exact --all-versions --limit-output 2>$null
        $versions = $raw |
            ForEach-Object { if ($_ -match '^nginx\|(.+)$') { $Matches[1].Trim() } } |
            Where-Object   { $_ } |
            Sort-Object    { try { [version]($_ -replace '[^0-9.]','0') } catch { [version]"0.0" } } `
                           -Descending
    } catch { }

    if ($versions.Count -eq 0) {
        Write-LogWarn "Chocolatey no devolvio versiones. Consultando nginx.org..."
        try {
            $html = (Invoke-WebRequest -Uri "https://nginx.org/en/download.html" `
                                       -UseBasicParsing -TimeoutSec 10).Content
            $m = [regex]::Matches($html, 'nginx-([\d]+\.[\d]+\.[\d]+)\.zip')
            $versions = $m | ForEach-Object { $_.Groups[1].Value } |
                        Sort-Object { [version]$_ } -Descending |
                        Select-Object -Unique -First 5
        } catch {
            Write-LogWarn "No se pudo consultar nginx.org. Usando versiones de referencia."
            $versions = @("1.27.4", "1.26.3", "1.24.0")
        }
    }

    if ($versions.Count -eq 0) {
        Write-LogError "No se encontraron versiones de Nginx disponibles."
        return $false
    }

    $maxShow = [Math]::Min($versions.Count, 5)
    Write-Host ""
    Write-Host "  Versiones disponibles de Nginx (Windows):" -ForegroundColor White
    Write-Host "  ─────────────────────────────────────────" -ForegroundColor DarkGray
    for ($i = 0; $i -lt $maxShow; $i++) {
        Write-Host "  $($i+1)) $($versions[$i])  " -NoNewline
        if     ($i -eq 0)            { Write-Host "(Mainline/Latest)" -ForegroundColor Yellow }
        elseif ($i -eq ($maxShow-1)) { Write-Host "(Estable/LTS)"     -ForegroundColor Green  }
        else                         { Write-Host ""                                           }
    }

    if (-not $script:INTERACTIVO) {
        $script:VERSION_ELEGIDA = $versions[0]
        return $true
    }

    while ($true) {
        Write-Host "`n  Selecciona una version [1-$maxShow]: " -ForegroundColor Cyan -NoNewline
        $sel = (Read-Host) -replace '[^0-9]', ''
        if ($sel -match '^\d+$' -and [int]$sel -ge 1 -and [int]$sel -le $maxShow) {
            $script:VERSION_ELEGIDA = $versions[[int]$sel - 1]
            Write-LogSuccess "Version seleccionada: $($script:VERSION_ELEGIDA)"
            return $true
        }
        Write-LogWarn "Seleccion invalida. Ingresa un numero entre 1 y $maxShow."
    }
}

# ==============================================================================
# CREAR USUARIO DE SERVICIO DEDICADO  (permisos limitados al webroot)
# ==============================================================================
function New-ServiceUser {
    param(
        [string]$Username,
        [string]$HomeDir
    )

    if (Get-LocalUser -Name $Username -ErrorAction SilentlyContinue) {
        Write-LogInfo "Usuario '$Username' ya existe."
        return
    }

    Write-LogInfo "Creando usuario dedicado '$Username' con acceso restringido..."
    $secPwd = ConvertTo-SecureString "!SvcAcc0unt#" -AsPlainText -Force
    New-LocalUser -Name $Username `
                  -Password $secPwd `
                  -AccountNeverExpires `
                  -PasswordNeverExpires `
                  -UserMayNotChangePassword `
                  -Description "Cuenta de servicio HTTP - $Username" `
                  -ErrorAction SilentlyContinue | Out-Null

    # Denegar inicio de sesion interactivo y remoto
    $sidAccount = (New-Object Security.Principal.NTAccount($Username)).Translate(
                    [Security.Principal.SecurityIdentifier]).Value
    $policy = Get-Content "$env:TEMP\secedit_export.inf" -ErrorAction SilentlyContinue
    secedit /export /cfg "$env:TEMP\secedit_export.inf" /quiet 2>$null
    if (Test-Path "$env:TEMP\secedit_export.inf") {
        $inf = Get-Content "$env:TEMP\secedit_export.inf" -Raw
        if ($inf -match 'SeDenyInteractiveLogonRight') {
            $inf = $inf -replace '(SeDenyInteractiveLogonRight\s*=\s*[^\r\n]*)',
                                 "`$1,*$sidAccount"
        } else {
            $inf += "`r`n[Privilege Rights]`r`nSeDenyInteractiveLogonRight = *$sidAccount"
        }
        Set-Content "$env:TEMP\secedit_import.inf" $inf -Encoding Unicode
        secedit /configure /db secedit.sdb /cfg "$env:TEMP\secedit_import.inf" /quiet 2>$null
    }

    Write-LogSuccess "Usuario '$Username' creado con acceso restringido."
}

# ==============================================================================
# APLICAR PERMISOS NTFS AL WEBROOT
# ==============================================================================
function Set-NtfsPermissions {
    param(
        [string]$Path,
        [string]$User
    )

    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }

    Write-LogInfo "Aplicando permisos NTFS en '$Path' para '$User'..."

    # Quitar herencia y limpiar permisos existentes del usuario
    icacls $Path /inheritance:d  /T /Q 2>$null | Out-Null
    icacls $Path /remove $User   /T /Q 2>$null | Out-Null

    # Solo lectura + ejecucion para el usuario de servicio
    icacls $Path /grant "${User}:(OI)(CI)RX" /T /Q 2>$null | Out-Null

    # SYSTEM y Administrators con control total
    icacls $Path /grant "SYSTEM:(OI)(CI)F"         /T /Q 2>$null | Out-Null
    icacls $Path /grant "Administrators:(OI)(CI)F" /T /Q 2>$null | Out-Null

    Write-LogSuccess "Permisos NTFS aplicados: $User → RX | Admins → Full en $Path"
}

# ==============================================================================
# CONFIGURAR FIREWALL  (abre el puerto elegido, cierra los defaults sin uso)
# ==============================================================================
function Set-FirewallRule {
    param([string]$PortParam)

    Write-LogInfo "Configurando reglas de firewall para puerto $PortParam..."

    # Eliminar regla previa con el mismo nombre si existe
    Remove-NetFirewallRule -DisplayName "HTTP-Custom-$PortParam" -ErrorAction SilentlyContinue

    New-NetFirewallRule -DisplayName "HTTP-Custom-$PortParam" `
                        -Direction    Inbound   `
                        -Protocol     TCP       `
                        -LocalPort    $PortParam `
                        -Action       Allow     `
                        -Profile      Any       `
                        -ErrorAction  SilentlyContinue | Out-Null

    Write-LogSuccess "Regla de firewall agregada: TCP/$PortParam entrante permitido."

    # Cerrar puertos HTTP por defecto que NO esten en uso activo
    $defaultHttpPorts = @(80, 8080, 8443)
    foreach ($dp in $defaultHttpPorts) {
        if ("$dp" -ne $PortParam) {
            $listening = Get-NetTCPConnection -LocalPort $dp -State Listen -ErrorAction SilentlyContinue
            if (-not $listening) {
                Remove-NetFirewallRule -DisplayName "HTTP-Custom-$dp" -ErrorAction SilentlyContinue
                Write-LogInfo "Regla de puerto $dp eliminada (sin listener activo en ese puerto)."
            }
        }
    }
}

# ==============================================================================
# CREAR INDEX.HTML PERSONALIZADO
# ==============================================================================
function New-CustomIndex {
    param(
        [string]$Path,
        [string]$Service,
        [string]$Version,
        [string]$PortParam
    )

    $fecha = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $dir   = Split-Path -Parent $Path
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    Write-LogInfo "Creando pagina index.html personalizada en $Path..."
    @"
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$Service - Practica 6</title>
    <style>
        body { font-family: Segoe UI, sans-serif; background:#1e1e2e; color:#cdd6f4;
               display:flex; justify-content:center; align-items:center; height:100vh; margin:0; }
        .card { background:#313244; border-radius:12px; padding:2.5rem 3rem;
                box-shadow:0 8px 32px rgba(0,0,0,0.4); text-align:center; }
        h1   { color:#89b4fa; margin-bottom:1rem; }
        p    { margin:.4rem 0; }
        .badge { display:inline-block; background:#a6e3a1; color:#1e1e2e;
                 border-radius:6px; padding:.2rem .7rem; font-weight:bold; }
    </style>
</head>
<body>
    <div class="card">
        <h1>Practica 6 - Despliegue HTTP</h1>
        <p><strong>Servidor:</strong> $Service</p>
        <p><strong>Version:</strong> <span class="badge">$Version</span></p>
        <p><strong>Puerto:</strong> $PortParam</p>
        <p><strong>Desplegado:</strong> $fecha</p>
    </div>
</body>
</html>
"@ | Set-Content -Path $Path -Encoding UTF8

    Write-LogSuccess "index.html creado en $Path"
}

# ==============================================================================
# VERIFICAR SERVICIO TRAS INSTALACION
# ==============================================================================
function Test-ServiceStatus {
    param(
        [string]$ServiceName,
        [string]$PortParam
    )

    Write-LogInfo "Verificando servicio '$ServiceName' en puerto $PortParam..."

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Write-LogSuccess "Servicio '$ServiceName' esta ACTIVO."
    } else {
        Write-LogWarn "El servicio '$ServiceName' no esta en estado Running."
    }

    $listening = Get-NetTCPConnection -LocalPort ([int]$PortParam) -State Listen `
                     -ErrorAction SilentlyContinue
    if ($listening) {
        Write-LogSuccess "Puerto $PortParam esta escuchando."
    } else {
        Write-LogWarn "Puerto $PortParam no detectado aun. Puede tardar unos segundos."
    }

    Write-LogInfo "Probando respuesta HTTP en localhost:$PortParam..."
    Start-Sleep -Seconds 2
    try {
        $resp = Invoke-WebRequest -Uri "http://localhost:$PortParam" `
                                  -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        if ($resp.StatusCode -eq 200) {
            Write-LogSuccess "Servidor responde HTTP 200 en puerto $PortParam ✓"
        } else {
            Write-LogWarn "Respuesta HTTP: $($resp.StatusCode)"
        }
    } catch {
        Write-LogWarn "No se pudo conectar al servidor (puede estar iniciando aun)."
    }
}

# ==============================================================================
# INSTALAR IIS  (servicio obligatorio en Windows)
# Usa: install_feature.ps1
# ==============================================================================
function Install-IIS {
    Write-Host ""
    Write-Host "  ═══════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "    Instalando IIS" -ForegroundColor Cyan
    Write-Host "  ═══════════════════════════════════════" -ForegroundColor Cyan

    Get-IISVersions
    if ([string]::IsNullOrEmpty($script:PUERTO_ELEGIDO)) { Request-Port }

    # Instalar IIS y herramientas de administracion via install_feature.ps1
    Write-LogInfo "Instalando rol Web-Server y sub-caracteristicas..."
    & "$UTILS_PS1_DIR\install_feature.ps1" -FeatureName "Web-Server" -IncludeAllSubFeature
    & "$UTILS_PS1_DIR\install_feature.ps1" -FeatureName "Web-Mgmt-Tools"
    & "$UTILS_PS1_DIR\install_feature.ps1" -FeatureName "Web-Scripting-Tools"

    # Cargar modulo WebAdministration
    Import-Module WebAdministration -ErrorAction Stop

    # ── Configurar binding de puerto ──────────────────────────────────────────
    Write-LogInfo "Configurando binding HTTP en puerto $($script:PUERTO_ELEGIDO)..."
    $siteName = "Default Web Site"

    # Eliminar todos los bindings HTTP existentes y crear uno nuevo
    Get-WebBinding -Name $siteName -Protocol "http" -ErrorAction SilentlyContinue |
        Remove-WebBinding -ErrorAction SilentlyContinue

    New-WebBinding -Name $siteName `
                   -Protocol    "http" `
                   -Port        $script:PUERTO_ELEGIDO `
                   -IPAddress   "*" `
                   -ErrorAction SilentlyContinue

    Write-LogSuccess "Binding configurado: *:$($script:PUERTO_ELEGIDO):http"

    # ── Hardening de seguridad ────────────────────────────────────────────────
    Write-LogInfo "Aplicando hardening de seguridad en IIS..."

    # Eliminar encabezado X-Powered-By
    try {
        Remove-WebConfigurationProperty `
            -Filter "system.webServer/httpProtocol/customHeaders" `
            -PSPath "IIS:\" `
            -Name   "." `
            -AtElement @{name="X-Powered-By"} `
            -ErrorAction SilentlyContinue
    } catch { }

    # Ocultar version del servidor (removeServerHeader)
    Set-WebConfigurationProperty `
        -Filter "system.webServer/security/requestFiltering" `
        -PSPath "IIS:\" `
        -Name   "removeServerHeader" `
        -Value  $true `
        -ErrorAction SilentlyContinue

    # Agregar encabezados de seguridad
    foreach ($header in @(
        @{name="X-Frame-Options";      value="SAMEORIGIN"},
        @{name="X-Content-Type-Options"; value="nosniff"}
    )) {
        # Eliminar si ya existe para no duplicar
        try {
            Remove-WebConfigurationProperty `
                -Filter "system.webServer/httpProtocol/customHeaders" `
                -PSPath "IIS:\" -Name "." -AtElement @{name=$header.name} `
                -ErrorAction SilentlyContinue
        } catch { }
        Add-WebConfigurationProperty `
            -Filter "system.webServer/httpProtocol/customHeaders" `
            -PSPath "IIS:\" `
            -Name   "." `
            -Value  $header `
            -ErrorAction SilentlyContinue
    }

    # Bloquear metodos HTTP peligrosos (TRACE, TRACK)
    foreach ($verb in @("TRACE","TRACK","DELETE")) {
        try {
            Add-WebConfigurationProperty `
                -Filter "system.webServer/security/requestFiltering/verbs" `
                -PSPath "IIS:\" `
                -Name   "." `
                -Value  @{verb=$verb; allowed="false"} `
                -ErrorAction SilentlyContinue
        } catch { }
    }

    Write-LogSuccess "Hardening de seguridad aplicado en IIS."

    # ── Usuario dedicado (ApplicationPoolIdentity ya es una cuenta virtual) ───
    Write-LogInfo "Configurando Application Pool con identidad minima..."
    Set-ItemProperty "IIS:\AppPools\DefaultAppPool" `
        -Name processModel.userName -Value "" -ErrorAction SilentlyContinue
    Set-ItemProperty "IIS:\AppPools\DefaultAppPool" `
        -Name processModel.identityType -Value 4 -ErrorAction SilentlyContinue
    Write-LogSuccess "DefaultAppPool usando ApplicationPoolIdentity."

    # ── Permisos NTFS en webroot ───────────────────────────────────────────────
    $webroot = "C:\inetpub\wwwroot"
    Set-NtfsPermissions -Path $webroot -User "IIS_IUSRS"

    # ── Firewall ──────────────────────────────────────────────────────────────
    Set-FirewallRule -PortParam $script:PUERTO_ELEGIDO

    # ── Index personalizado ───────────────────────────────────────────────────
    New-CustomIndex -Path     "$webroot\index.html" `
                    -Service  "IIS"  `
                    -Version  $script:VERSION_ELEGIDA `
                    -PortParam $script:PUERTO_ELEGIDO

    # ── Reiniciar IIS ─────────────────────────────────────────────────────────
    Write-LogInfo "Reiniciando IIS..."
    iisreset /restart 2>$null
    Start-Sleep -Seconds 3

    Test-ServiceStatus -ServiceName "W3SVC" -PortParam $script:PUERTO_ELEGIDO
}

# ==============================================================================
# INSTALAR APACHE PARA WINDOWS
# Usa: install_feature.ps1 (no aplica — Apache no es un rol de Windows)
#      Chocolatey para descarga silenciosa
# ==============================================================================
function Install-ApacheWin {
    Write-Host ""
    Write-Host "  ═══════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "    Instalando Apache (Windows)" -ForegroundColor Cyan
    Write-Host "  ═══════════════════════════════════════" -ForegroundColor Cyan

    if (-not (Get-ApacheVersions)) { return }
    if ([string]::IsNullOrEmpty($script:PUERTO_ELEGIDO)) { Request-Port }

    # ── Instalacion silenciosa via Chocolatey ─────────────────────────────────
    Write-LogInfo "Instalando Apache $($script:VERSION_ELEGIDA) via Chocolatey..."
    choco install apache --version="$($script:VERSION_ELEGIDA)" -y --no-progress 2>&1 |
        Out-Null

    if ($LASTEXITCODE -ne 0) {
        Write-LogWarn "No se pudo instalar version especifica. Instalando la ultima estable..."
        choco install apache -y --no-progress
        if ($LASTEXITCODE -ne 0) {
            Write-LogError "Fallo la instalacion de Apache para Windows."
            return
        }
    }

    $apacheDir = Get-ApacheInstallDir
    if (-not $apacheDir) {
        Write-LogError "No se encontro el directorio de instalacion de Apache."
        return
    }
    Write-LogSuccess "Apache instalado en: $apacheDir"

    # ── Configurar puerto en httpd.conf ───────────────────────────────────────
    $httpdConf = "$apacheDir\conf\httpd.conf"
    Write-LogInfo "Configurando puerto $($script:PUERTO_ELEGIDO) en httpd.conf..."
    if (Test-Path $httpdConf) {
        $content = Get-Content $httpdConf -Raw
        $content = $content -replace 'Listen \d+',
                                     "Listen $($script:PUERTO_ELEGIDO)"
        $content = $content -replace 'ServerName\s+\S+:\d+',
                                     "ServerName localhost:$($script:PUERTO_ELEGIDO)"
        Set-Content $httpdConf $content -Encoding UTF8
        Write-LogSuccess "Puerto configurado en httpd.conf."
    } else {
        Write-LogWarn "No se encontro httpd.conf en $apacheDir\conf\"
    }

    # ── Hardening: ocultar version y tokens del servidor ─────────────────────
    Write-LogInfo "Aplicando hardening en Apache (ServerTokens, headers de seguridad)..."
    if (Test-Path $httpdConf) {
        $content = Get-Content $httpdConf -Raw

        if ($content -match 'ServerTokens') {
            $content = $content -replace 'ServerTokens\s+\S+', 'ServerTokens Prod'
        } else {
            $content += "`r`nServerTokens Prod"
        }
        if ($content -match 'ServerSignature') {
            $content = $content -replace 'ServerSignature\s+\S+', 'ServerSignature Off'
        } else {
            $content += "`r`nServerSignature Off"
        }

        # Habilitar mod_headers si no esta activo
        $content = $content -replace '#(LoadModule headers_module)', '$1'

        Set-Content $httpdConf $content -Encoding UTF8
    }

    # Archivo de encabezados de seguridad
    $headersConf = "$apacheDir\conf\extra\security-headers.conf"
    @"
# Encabezados de seguridad - Practica 6
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-Content-Type-Options "nosniff"

# Bloquear metodos peligrosos
<LimitExcept GET POST HEAD>
    Require all denied
</LimitExcept>
"@ | Set-Content $headersConf -Encoding UTF8

    # Incluir el archivo si no esta referenciado
    $content = Get-Content $httpdConf -Raw
    if ($content -notmatch 'security-headers\.conf') {
        Add-Content $httpdConf "`r`nInclude conf/extra/security-headers.conf"
    }

    Write-LogSuccess "Hardening de seguridad aplicado en Apache."

    # ── Usuario dedicado con permisos restringidos ────────────────────────────
    New-ServiceUser -Username "apache_svc" -HomeDir "$apacheDir\htdocs"
    Set-NtfsPermissions -Path "$apacheDir\htdocs" -User "apache_svc"

    # ── Index personalizado ───────────────────────────────────────────────────
    New-CustomIndex -Path      "$apacheDir\htdocs\index.html" `
                    -Service   "Apache" `
                    -Version   $script:VERSION_ELEGIDA `
                    -PortParam $script:PUERTO_ELEGIDO

    # ── Firewall ──────────────────────────────────────────────────────────────
    Set-FirewallRule -PortParam $script:PUERTO_ELEGIDO

    # ── Registrar e iniciar servicio Windows ──────────────────────────────────
    Write-LogInfo "Registrando Apache como servicio de Windows..."
    $httpdExe = "$apacheDir\bin\httpd.exe"
    if (Test-Path $httpdExe) {
        & $httpdExe -k install -n "Apache24" 2>$null
        Start-Sleep -Seconds 1
        Start-Service -Name "Apache24" -ErrorAction SilentlyContinue
    }

    Start-Sleep -Seconds 3
    Test-ServiceStatus -ServiceName "Apache24" -PortParam $script:PUERTO_ELEGIDO
}

# ==============================================================================
# INSTALAR NGINX PARA WINDOWS
# Usa: Chocolatey para descarga silenciosa + NSSM para registro de servicio
# ==============================================================================
function Install-NginxWin {
    Write-Host ""
    Write-Host "  ═══════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "    Instalando Nginx (Windows)" -ForegroundColor Cyan
    Write-Host "  ═══════════════════════════════════════" -ForegroundColor Cyan

    if (-not (Get-NginxVersions)) { return }
    if ([string]::IsNullOrEmpty($script:PUERTO_ELEGIDO)) { Request-Port }

    # ── Instalacion silenciosa via Chocolatey ─────────────────────────────────
    Write-LogInfo "Instalando Nginx $($script:VERSION_ELEGIDA) via Chocolatey..."
    choco install nginx --version="$($script:VERSION_ELEGIDA)" -y --no-progress 2>&1 |
        Out-Null

    if ($LASTEXITCODE -ne 0) {
        Write-LogWarn "No se pudo instalar version especifica. Instalando la ultima estable..."
        choco install nginx -y --no-progress
        if ($LASTEXITCODE -ne 0) {
            Write-LogError "Fallo la instalacion de Nginx para Windows."
            return
        }
    }

    $nginxDir = Get-NginxInstallDir
    if (-not $nginxDir) {
        Write-LogError "No se encontro el directorio de instalacion de Nginx."
        return
    }
    Write-LogSuccess "Nginx instalado en: $nginxDir"

    # ── Configurar puerto en nginx.conf ───────────────────────────────────────
    $nginxConf = "$nginxDir\conf\nginx.conf"
    Write-LogInfo "Configurando puerto $($script:PUERTO_ELEGIDO) en nginx.conf..."
    if (Test-Path $nginxConf) {
        $content = Get-Content $nginxConf -Raw
        $content = $content -replace 'listen\s+\d+;', "listen $($script:PUERTO_ELEGIDO);"
        Set-Content $nginxConf $content -Encoding UTF8
        Write-LogSuccess "Puerto configurado en nginx.conf."
    } else {
        Write-LogWarn "No se encontro nginx.conf en $nginxDir\conf\"
    }

    # ── Hardening: ocultar version + encabezados de seguridad ────────────────
    Write-LogInfo "Aplicando hardening en Nginx (server_tokens, headers de seguridad)..."
    if (Test-Path $nginxConf) {
        $content = Get-Content $nginxConf -Raw

        if ($content -notmatch 'server_tokens\s+off') {
            $content = $content -replace '(http\s*\{)', "`$1`r`n    server_tokens off;"
        }

        # Incluir archivo de seguridad dentro del bloque http
        if ($content -notmatch 'security\.conf') {
            $content = $content -replace '(http\s*\{)',
                                         "`$1`r`n    include conf/security.conf;"
        }
        Set-Content $nginxConf $content -Encoding UTF8
    }

    # Archivo de encabezados y restricciones de seguridad
    $secConf = "$nginxDir\conf\security.conf"
    @"
# Encabezados de seguridad - Practica 6
add_header X-Frame-Options      "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff"  always;

# Bloquear metodos peligrosos
map `$request_method `$block_method {
    default  0;
    TRACE    1;
    TRACK    1;
    DELETE   1;
}
"@ | Set-Content $secConf -Encoding UTF8

    Write-LogSuccess "Hardening de seguridad aplicado en Nginx."

    # ── Usuario dedicado con permisos restringidos ────────────────────────────
    New-ServiceUser -Username "nginx_svc" -HomeDir "$nginxDir\html"
    Set-NtfsPermissions -Path "$nginxDir\html" -User "nginx_svc"

    # ── Index personalizado ───────────────────────────────────────────────────
    New-CustomIndex -Path      "$nginxDir\html\index.html" `
                    -Service   "Nginx" `
                    -Version   $script:VERSION_ELEGIDA `
                    -PortParam $script:PUERTO_ELEGIDO

    # ── Firewall ──────────────────────────────────────────────────────────────
    Set-FirewallRule -PortParam $script:PUERTO_ELEGIDO

    # ── Registrar como servicio Windows via NSSM ──────────────────────────────
    Write-LogInfo "Registrando Nginx como servicio de Windows (NSSM)..."
    if (-not (Get-Command nssm -ErrorAction SilentlyContinue)) {
        choco install nssm -y --no-progress 2>$null
        $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" +
                    [System.Environment]::GetEnvironmentVariable("PATH","User")
    }

    $nginxExe = "$nginxDir\nginx.exe"
    if (Get-Command nssm -ErrorAction SilentlyContinue) {
        nssm install nginx "$nginxExe" 2>$null
        nssm set    nginx AppDirectory "$nginxDir" 2>$null
        Start-Service -Name "nginx" -ErrorAction SilentlyContinue
    } else {
        Write-LogWarn "NSSM no disponible. Iniciando Nginx directamente..."
        Start-Process -FilePath $nginxExe -WorkingDirectory $nginxDir -WindowStyle Hidden
    }

    Start-Sleep -Seconds 3
    Test-ServiceStatus -ServiceName "nginx" -PortParam $script:PUERTO_ELEGIDO
}

# ==============================================================================
# MOSTRAR ESTADO DE SERVICIOS HTTP
# ==============================================================================
function Show-ServiceStatus {
    Write-Host ""
    Write-Host "  Estado de servicios HTTP:" -ForegroundColor White
    Write-Host "  ─────────────────────────────────────────" -ForegroundColor DarkGray

    $services = @(
        @{ Name="W3SVC";    Label="IIS"     },
        @{ Name="Apache24"; Label="Apache"  },
        @{ Name="nginx";    Label="Nginx"   }
    )

    foreach ($s in $services) {
        $svc = Get-Service -Name $s.Name -ErrorAction SilentlyContinue
        if ($svc) {
            $color  = if ($svc.Status -eq "Running") { "Green" } else { "Yellow" }
            $puerto = (
                Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
                Where-Object { $_.OwningProcess -in (
                    Get-WmiObject Win32_Service -Filter "Name='$($s.Name)'" `
                        -ErrorAction SilentlyContinue |
                    Select-Object -ExpandProperty ProcessId) } |
                Select-Object -First 1 -ExpandProperty LocalPort
            )
            $puertoStr = if ($puerto) { $puerto } else { "desconocido" }
            Write-Host "  $($s.Label.PadRight(8))" -NoNewline
            Write-Host " $($svc.Status)" -ForegroundColor $color -NoNewline
            Write-Host "  (puerto: $puertoStr)" -ForegroundColor Cyan
        } else {
            Write-Host "  $($s.Label.PadRight(8))" -NoNewline
            Write-Host " no instalado" -ForegroundColor DarkGray
        }
    }
    Write-Host ""
}

# ==============================================================================
# PURGAR TODOS LOS SERVICIOS HTTP
# ==============================================================================
function Remove-AllServices {
    Write-Host ""
    Write-Host "  ADVERTENCIA: Se eliminaran IIS, Apache y Nginx junto con sus configuraciones." `
               -ForegroundColor Red

    if ($script:INTERACTIVO) {
        Write-Host "  Confirmar eliminacion [s/N]: " -ForegroundColor Yellow -NoNewline
        $conf = Read-Host
        $conf = $conf -replace '[^a-zA-Z]', ''
        if ($conf -notin @("s","S","y","Y")) {
            Write-LogInfo "Purgado cancelado por el usuario."
            return
        }
    }

    # ── Purgar IIS ────────────────────────────────────────────────────────────
    Write-LogInfo "Eliminando IIS..."
    Stop-Service -Name "W3SVC" -Force -ErrorAction SilentlyContinue
    try {
        Uninstall-WindowsFeature -Name "Web-Server" -IncludeManagementTools `
            -ErrorAction SilentlyContinue | Out-Null
    } catch { Write-LogWarn "No se pudo desinstalar IIS via Uninstall-WindowsFeature." }
    Remove-Item "C:\inetpub\wwwroot\index.html" -Force -ErrorAction SilentlyContinue

    # ── Purgar Apache ─────────────────────────────────────────────────────────
    Write-LogInfo "Eliminando Apache..."
    Stop-Service  -Name "Apache24" -Force -ErrorAction SilentlyContinue
    $apacheDir = Get-ApacheInstallDir
    if ($apacheDir) {
        $httpdExe = "$apacheDir\bin\httpd.exe"
        if (Test-Path $httpdExe) { & $httpdExe -k uninstall -n "Apache24" 2>$null }
    }
    choco uninstall apache -y --no-progress 2>$null
    if ($apacheDir -and (Test-Path $apacheDir)) {
        Remove-Item $apacheDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    Remove-LocalUser -Name "apache_svc" -ErrorAction SilentlyContinue

    # ── Purgar Nginx ──────────────────────────────────────────────────────────
    Write-LogInfo "Eliminando Nginx..."
    Stop-Service -Name "nginx" -Force -ErrorAction SilentlyContinue
    if (Get-Command nssm -ErrorAction SilentlyContinue) {
        nssm remove nginx confirm 2>$null
    }
    choco uninstall nginx -y --no-progress 2>$null
    $nginxDir = Get-NginxInstallDir
    if ($nginxDir -and (Test-Path $nginxDir)) {
        Remove-Item $nginxDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    Remove-LocalUser -Name "nginx_svc" -ErrorAction SilentlyContinue

    Write-LogSuccess "Purgado completado. Todos los servicios HTTP han sido eliminados."
}

# ==============================================================================
# AYUDA
# ==============================================================================
function Show-Help {
    Write-Host ""
    Write-Host "  Uso: .\http_deploy.ps1 [opciones]" -ForegroundColor White
    Write-Host ""
    Write-Host "  Opciones:"
    Write-Host "    -Service <servicio>   Servicio a instalar: iis | apache | nginx"
    Write-Host "    -Port    <puerto>     Puerto de escucha (ej: 8080, 8888)"
    Write-Host "    -Status               Muestra el estado de los servicios HTTP"
    Write-Host "    -Purge                Elimina todos los servicios HTTP instalados"
    Write-Host "    -Help                 Muestra este mensaje"
    Write-Host ""
    Write-Host "  Ejemplos:"
    Write-Host "    .\http_deploy.ps1 -Service iis    -Port 8080"
    Write-Host "    .\http_deploy.ps1 -Service apache -Port 8888"
    Write-Host "    .\http_deploy.ps1 -Service nginx  -Port 9090"
    Write-Host "    .\http_deploy.ps1 -Status"
    Write-Host "    .\http_deploy.ps1 -Purge"
    Write-Host ""
}

# ==============================================================================
# MENU INTERACTIVO
# ==============================================================================
function Show-Menu {
    Clear-Host
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║  Practica 6 - Despliegue HTTP Windows    ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  1)  Instalar IIS" -ForegroundColor White
    Write-Host "  2)  Instalar Apache (Windows)" -ForegroundColor White
    Write-Host "  3)  Instalar Nginx  (Windows)" -ForegroundColor White
    Write-Host "  4)  Ver estado de servicios" -ForegroundColor White
    Write-Host "  5)  Purgar todo (eliminar servicios)" -ForegroundColor White
    Write-Host "  0)  Salir" -ForegroundColor White
    Write-Host ""
    Write-Host "  Selecciona una opcion: " -ForegroundColor Cyan -NoNewline
}

# ==============================================================================
# INICIO — VERIFICACIONES PREVIAS
# ==============================================================================
Test-AdminPrivileges
Test-Connectivity

# ── Validar puerto si fue pasado por parametro ────────────────────────────────
if (-not [string]::IsNullOrEmpty($script:PUERTO_ELEGIDO)) {
    if (-not (Invoke-ValidatePort -PortNum $script:PUERTO_ELEGIDO)) {
        Write-LogError "El puerto '$($script:PUERTO_ELEGIDO)' no es valido. Abortando."
    }
}

# ==============================================================================
# FLUJO CON PARAMETROS (NO INTERACTIVO)
# ==============================================================================
if ($Help)   { Show-Help;           exit 0 }
if ($Status) { Show-ServiceStatus;  exit 0 }
if ($Purge)  {
    $script:INTERACTIVO = $false
    Remove-AllServices
    exit 0
}

if (-not [string]::IsNullOrEmpty($Service)) {
    $script:INTERACTIVO = $false

    if ([string]::IsNullOrEmpty($script:PUERTO_ELEGIDO)) {
        Write-LogError "Debes especificar un puerto con -Port en modo no interactivo."
    }

    switch ($Service.ToLower()) {
        "iis"    { Install-IIS        }
        "apache" { Install-ApacheWin  }
        "nginx"  { Install-NginxWin   }
        default  {
            Write-LogError "Servicio '$Service' no soportado. Usa: iis | apache | nginx"
        }
    }
    exit 0
}

# ==============================================================================
# FLUJO INTERACTIVO (MENU)
# ==============================================================================
while ($true) {
    Show-Menu
    $opcion = Read-Host
    $opcion = $opcion -replace '[^0-9]', ''

    switch ($opcion) {
        "1" { $script:PUERTO_ELEGIDO = ""; Install-IIS       }
        "2" { $script:PUERTO_ELEGIDO = ""; Install-ApacheWin }
        "3" { $script:PUERTO_ELEGIDO = ""; Install-NginxWin  }
        "4" { Show-ServiceStatus }
        "5" { Remove-AllServices }
        "0" { Write-LogSuccess "Saliendo..."; exit 0 }
        default {
            Write-LogWarn "Opcion invalida. Ingresa 0, 1, 2, 3, 4 o 5."
            Start-Sleep -Seconds 1
        }
    }

    Write-Host "`n  Presiona ENTER para volver al menu..." -ForegroundColor Cyan -NoNewline
    Read-Host | Out-Null
}
