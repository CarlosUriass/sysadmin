#Requires -RunAsAdministrator
#Requires -Version 5.1
param(
    [string]$Service       = "",
    [int]   $Port          = 0,
    [string]$ServiceVersion= "",
    [switch]$ListVersions,
    [switch]$Status,
    [switch]$Purge,
    [switch]$Help
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# ---------------------------------------------------------------------------
# LOGGING
# ---------------------------------------------------------------------------
function Log-Info    ([string]$m) { Write-Host "[INFO]  $m" -ForegroundColor Cyan   }
function Log-OK      ([string]$m) { Write-Host "[OK]    $m" -ForegroundColor Green  }
function Log-Warn    ([string]$m) { Write-Host "[WARN]  $m" -ForegroundColor Yellow }
function Log-Error   ([string]$m) { Write-Host "[FAIL]  $m" -ForegroundColor Red    }

# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------
function Test-PortInUse ([int]$p) {
    return [bool](Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue)
}

function Get-FreePorts ([int]$base) {
    $out = @()
    for ($i = $base + 1; $i -le [Math]::Min($base + 20, 65535); $i++) {
        if (-not (Test-PortInUse $i)) { $out += $i; if ($out.Count -ge 3) { break } }
    }
    return $out
}

function Ensure-Port80Free {
    $blockingProcess = Get-NetTCPConnection -LocalPort 80 -State Listen -ErrorAction SilentlyContinue
    if ($blockingProcess) {
        $pid = $blockingProcess.OwningProcess
        $procName = (Get-Process -Id $pid -ErrorAction SilentlyContinue).ProcessName
        Log-Warn "El puerto 80 esta ocupado por el proceso '$procName' (PID: $pid)."
        Log-Warn "IIS requiere el puerto 80 libre temporalmente durante su instalacion."
        return $false
    }
    return $true
}

function Ensure-Chocolatey {
    if (Get-Command choco -ErrorAction SilentlyContinue) { return }
    Log-Warn "Instalando Chocolatey..."
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072
    Invoke-Expression ((New-Object Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    $env:Path += ";$env:ALLUSERSPROFILE\chocolatey\bin"
}

function Get-AvailableVersions ([string]$svc) {
    Ensure-Chocolatey
    switch ($svc.ToLower()) {
        "iis"    { return @("10.0") }
        "apache" {
            $raw = choco search apache-httpd --exact --all-versions 2>$null | Select-String "apache-httpd\s+\d"
            $v = $raw | ForEach-Object { ($_.ToString().Trim() -split '\s+')[1] }
            if (-not $v) { $v = @("2.4.58","2.4.55","2.4.54") }
            return $v | Select-Object -First 5
        }
        "nginx"  {
            $raw = choco search nginx --exact --all-versions 2>$null | Select-String "^nginx\s+\d"
            $v = $raw | ForEach-Object { ($_.ToString().Trim() -split '\s+')[1] }
            if (-not $v) { $v = @("1.29.6","1.27.4","1.26.3") }
            return $v | Select-Object -First 5
        }
    }
}

function Write-IndexHtml ([string]$path, [string]$svc, [string]$ver, [int]$port) {
    $dir = Split-Path $path -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $ts   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $html = "<html><body><h1>$svc $ver - Puerto $port</h1><p>$ts</p></body></html>"
    [IO.File]::WriteAllText($path, $html, [Text.UTF8Encoding]::new($false))
    Log-OK "index.html -> $path"
}

function Set-Firewall ([int]$port, [string]$svc) {
    $name = "HTTP-Allow-$svc-$port"
    if (-not (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $name -Direction Inbound -Protocol TCP -LocalPort $port -Action Allow | Out-Null
    }
    Log-Info "Firewall: puerto $port habilitado para $svc"
}

# ---------------------------------------------------------------------------
# IIS
# ---------------------------------------------------------------------------
function Install-IIS ([int]$port, [string]$ver) {
    if (-not (Ensure-Port80Free)) {
        Log-Error "Despliegue cancelado. Limpia el puerto 80 primero."
        return $false
    }

    Log-Info "Instalando IIS en puerto $port..."

    # 1. Habilitar features minimas
    $features = @(
        "IIS-WebServerRole","IIS-WebServer",
        "IIS-CommonHttpFeatures","IIS-DefaultDocument",
        "IIS-StaticContent","IIS-RequestFiltering","IIS-ManagementConsole"
    )
    foreach ($f in $features) {
        $state = (Get-WindowsOptionalFeature -Online -FeatureName $f -EA SilentlyContinue).State
        if ($state -ne "Enabled") {
            Log-Info "Habilitando: $f"
            Enable-WindowsOptionalFeature -Online -FeatureName $f -All -NoRestart | Out-Null
        }
    }

    # 2. Modificar el puerto forzando la liberacion del sitio
    Import-Module WebAdministration
    Start-Sleep 4 # Breve respiro para que el proveedor IIS:\ se registre

    if (Get-Website -Name "Default Web Site" -ErrorAction SilentlyContinue) {
        Log-Info "Deteniendo sitio temporalmente para liberar bloqueos..."
        
        # El truco de magia: detener el Pool y el Sitio libera el applicationHost.config
        Stop-WebAppPool -Name "DefaultAppPool" -ErrorAction SilentlyContinue
        Stop-Website -Name "Default Web Site" -ErrorAction SilentlyContinue
        Start-Sleep 1

        Log-Info "Aplicando nuevo puerto $port..."
        try {
            Remove-WebBinding -Name "Default Web Site" -BindingInformation "*:80:" -ErrorAction SilentlyContinue
            New-WebBinding -Name "Default Web Site" -Port $port -Protocol "http" -ErrorAction Stop
            Log-OK "Binding actualizado exitosamente"
        } catch {
            Log-Warn "Fallo WebBinding, usando appcmd forzado: $($_.Exception.Message)"
            $appcmd = "$env:SystemRoot\system32\inetsrv\appcmd.exe"
            & $appcmd set site "Default Web Site" /bindings:"http/*:${port}:" 2>&1 | Out-Null
        }

        # Volver a encender todo
        Start-WebAppPool -Name "DefaultAppPool" -ErrorAction SilentlyContinue
        Start-Website -Name "Default Web Site" -ErrorAction SilentlyContinue
        Start-Service W3SVC, WAS -ErrorAction SilentlyContinue
    } else {
        Log-Warn "No se encontro 'Default Web Site'. Verifica la instalacion."
    }

    # 3. Pagina de prueba
    Write-IndexHtml -path "C:\inetpub\wwwroot\index.html" -svc "IIS" -ver $ver -port $port

    # 4. Validar
    if (Test-PortInUse $port) {
        Log-OK "IIS escuchando en puerto $port"
        return $true
    }
    
    Log-Error "IIS no responde en puerto $port"
    Log-Error "W3SVC: $((Get-Service W3SVC -EA SilentlyContinue).Status)"
    return $false
}

function Install-Nginx ([int]$port, [string]$ver) {
    Log-Info "Instalando Nginx $ver en puerto $port..."
    Ensure-Chocolatey
    choco install nginx --version=$ver -y --no-progress --force 2>&1 | Out-Null

    $root = Get-NginxPath
    if (-not $root) { return $false }

    $conf = "$root\conf\nginx.conf"
    if (-not (Test-Path $conf)) { Log-Error "nginx.conf no encontrado"; return $false }

    $c = Get-Content $conf -Raw
    $c = $c -replace '(?m)(listen\s+)\d+(;)',       ('$1' + $port + '$2')
    $c = $c -replace '(?m)(listen\s+\[::\]:)\d+(;)', ('$1' + $port + '$2')
    [IO.File]::WriteAllText($conf, $c, [Text.UTF8Encoding]::new($false))

    Write-IndexHtml -path "$root\html\index.html" -svc "Nginx" -ver $ver -port $port

    Stop-Process -Name nginx -Force -EA SilentlyContinue
    Start-Sleep 1
    Push-Location $root
    Start-Process -FilePath "$root\nginx.exe" -NoNewWindow
    Pop-Location
    Start-Sleep 3

    if (Test-PortInUse $port) { Log-OK "Nginx escuchando en puerto $port"; return $true }
    
    Log-Error "Nginx no responde en $port"
    return $false
}

# ---------------------------------------------------------------------------
# ORQUESTADOR
# ---------------------------------------------------------------------------
function Deploy ([string]$svc, [int]$port, [string]$ver) {
    Log-Info "Desplegando $svc v$ver en puerto $port..."

    if (Test-PortInUse $port) {
        Log-Error "Puerto $port ocupado. Disponibles: $((Get-FreePorts $port) -join ', ')"
        return
    }

    $ok = switch ($svc.ToLower()) {
        "iis"    { Install-IIS    -port $port -ver $ver }
        "apache" { Install-Apache -port $port -ver $ver }
        "nginx"  { Install-Nginx  -port $port -ver $ver }
        default  { Log-Error "Servicio no soportado: $svc"; return }
    }

    if ($ok) {
        Set-Firewall -port $port -svc $svc
        Log-OK "$svc desplegado correctamente en puerto $port"
    } else {
        Log-Error "Despliegue de $svc fallido"
    }
}

# ---------------------------------------------------------------------------
# STATUS / PURGE
# ---------------------------------------------------------------------------
function Show-Status {
    Write-Host "`n--- SERVICIOS ---" -ForegroundColor White
    Get-Service W3SVC,WAS,Apache2.4,nginx -EA SilentlyContinue | Select-Object Name,Status | Format-Table -AutoSize

    Write-Host "--- PUERTOS EN ESCUCHA ---" -ForegroundColor White
    Get-NetTCPConnection -State Listen -EA SilentlyContinue | Where-Object { $_.LocalPort -lt 10000 -and $_.LocalPort -ge 80 } | Select-Object LocalAddress,LocalPort,OwningProcess | Sort-Object LocalPort | Format-Table -AutoSize
}

function Invoke-Purge {
    Log-Warn "Purgando instalaciones..."
    iisreset /stop /noforce 2>&1 | Out-Null
    Stop-Service AppHostSvc,WAS,W3SVC,Apache2.4,nginx -Force -EA SilentlyContinue
    Stop-Process -Name nginx,httpd -Force -EA SilentlyContinue
    Start-Sleep 2

    sc.exe delete nginx    2>&1 | Out-Null
    sc.exe delete Apache2.4 2>&1 | Out-Null

    Ensure-Chocolatey
    choco uninstall nginx apache-httpd -y --remove-dependencies 2>&1 | Out-Null
    Disable-WindowsOptionalFeature -Online -FeatureName "IIS-WebServerRole" -NoRestart -Remove -EA SilentlyContinue | Out-Null

    Remove-Item "C:\tools\Apache24","C:\tools\nginx" -Recurse -Force -EA SilentlyContinue
    Get-NetFirewallRule -DisplayName "HTTP-Allow-*" -EA SilentlyContinue | Remove-NetFirewallRule
    Log-OK "Purga completada"
}

# ---------------------------------------------------------------------------
# ENTRADA INTERACTIVA
# ---------------------------------------------------------------------------
function Ask-Port {
    while ($true) {
        $raw = Read-Host "Puerto (80 o 1024-65535)"
        $p   = 0
        if ([int]::TryParse($raw, [ref]$p) -and ($p -eq 80 -or ($p -ge 1024 -and $p -le 65535))) {
            if (-not (Test-PortInUse $p)) { return $p }
            Log-Error "Puerto $p ocupado. Disponibles: $((Get-FreePorts $p) -join ', ')"
        } else { Log-Warn "Puerto invalido" }
    }
}

function Ask-Version ([string]$svc) {
    $vers = Get-AvailableVersions $svc
    Write-Host "Versiones disponibles:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $vers.Count; $i++) { Write-Host "  $($i+1)) $($vers[$i])" }
    $sel = Read-Host "Opcion (Enter = mas reciente)"
    $idx = 0
    if ([int]::TryParse($sel,[ref]$idx) -and $idx -ge 1 -and $idx -le $vers.Count) { return $vers[$idx - 1] }
    return $vers[0]
}

# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
function Main {
    if ($Help) {
        Write-Host "Uso: .\http_deploy.ps1 [-Service iis|apache|nginx] [-Port N] [-ServiceVersion V] [-Status] [-Purge] [-ListVersions]"
        return
    }
    if ($Status)  { Show-Status;  return }
    if ($Purge)   { Invoke-Purge; return }

    if ($Service -ne "") {
        if ($ListVersions) {
            Get-AvailableVersions $Service | ForEach-Object { Write-Host "  - $_" }
            return
        }
        if ($Port -eq 0) { Log-Error "Especifica -Port <num>"; return }
        $ver = if ($ServiceVersion) { $ServiceVersion } else { (Get-AvailableVersions $Service)[0] }
        Deploy -svc $Service -port $Port -ver $ver
        return
    }

    while ($true) {
        Write-Host "`n=== APROVISIONAMIENTO HTTP ===" -ForegroundColor Cyan
        Write-Host "  1) IIS`n  2) Apache`n  3) Nginx`n  4) Estado`n  5) Purgar`n  q) Salir"
        switch ((Read-Host "Opcion").ToLower()) {
            "1" { Deploy "iis"    (Ask-Port) "10.0" }
            "2" { Deploy "apache" (Ask-Port) (Ask-Version "apache") }
            "3" { Deploy "nginx"  (Ask-Port) (Ask-Version "nginx")  }
            "4" { Show-Status }
            "5" { Invoke-Purge }
            "q" { return }
            default { Log-Warn "Opcion no valida" }
        }
    }
}

Main